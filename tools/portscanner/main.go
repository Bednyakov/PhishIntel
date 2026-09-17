package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Port struct {
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	Service    string `json:"service,omitempty"`
	Technology string `json:"technology,omitempty"`
	Version    string `json:"version,omitempty"`
	Banner     string `json:"banner,omitempty"`
}

type Result struct {
	Status            string   `json:"status"`
	Target            string   `json:"target"`
	ResolvedAddresses []string `json:"resolved_addresses,omitempty"`
	Ports             []Port   `json:"ports"`
	OpenPortCount     int      `json:"open_port_count"`
	Technologies      []string `json:"technologies"`
	Error             string   `json:"error,omitempty"`
	DurationMS        int64    `json:"duration_ms"`
}

var defaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5672, 5900, 6379, 6443, 8080, 8443, 9200, 27017}

var techPatterns = []struct{ name, pattern string }{
	{"nginx", `(?i)nginx(?:/|\s)`}, {"Apache", `(?i)apache`}, {"Microsoft IIS", `(?i)microsoft-iis`},
	{"OpenSSH", `(?i)openssh`}, {"MySQL", `(?i)mysql`}, {"PostgreSQL", `(?i)postgres`},
	{"Redis", `(?i)redis`}, {"MongoDB", `(?i)mongodb`}, {"Docker", `(?i)docker`},
}

func main() {
	target := flag.String("target", "", "hostname or IP address")
	timeout := flag.Duration("timeout", 3*time.Second, "per-connection timeout")
	flag.Parse()
	started := time.Now()
	result := Result{Status: "ok", Target: *target, Ports: []Port{}, Technologies: []string{}}
	if *target == "" {
		result.Status, result.Error = "invalid_target", "target is required"
		writeResult(result, started)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, *target)
	if err != nil {
		result.Status, result.Error = "unavailable", err.Error()
		writeResult(result, started)
		return
	}
	result.ResolvedAddresses = unique(addresses)
	ports := scan(ctx, *target, result.ResolvedAddresses[0], *timeout)
	result.Ports = ports
	result.OpenPortCount = len(ports)
	tech := map[string]bool{}
	for _, p := range ports {
		if p.Technology != "" {
			tech[p.Technology] = true
		}
	}
	for name := range tech {
		result.Technologies = append(result.Technologies, name)
	}
	sort.Strings(result.Technologies)
	writeResult(result, started)
}

func scan(ctx context.Context, host, address string, timeout time.Duration) []Port {
	type item struct{ port Port }
	jobs := make(chan int)
	results := make(chan item, len(defaultPorts))
	workers := 16
	if workers > len(defaultPorts) {
		workers = len(defaultPorts)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if port, ok := probe(ctx, host, address, p, timeout); ok {
					results <- item{port}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, p := range defaultPorts {
			select {
			case jobs <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	ports := []Port{}
	for item := range results {
		ports = append(ports, item.port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports
}

func probe(ctx context.Context, host, address string, port int, timeout time.Duration) (Port, bool) {
	service := serviceName(port)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address, fmt.Sprint(port)))
	if err != nil {
		return Port{}, false
	}
	defer conn.Close()
	result := Port{Port: port, Protocol: "tcp", State: "open", Service: service}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if port == 80 || port == 8080 || port == 8000 || port == 8443 || port == 443 {
		result.Banner, result.Technology, result.Version = httpProbe(host, port)
	} else {
		buffer := make([]byte, 512)
		n, _ := conn.Read(buffer)
		result.Banner = clean(string(buffer[:n]))
		result.Technology, result.Version = identify(result.Banner)
	}
	return result, true
}

func httpProbe(host string, port int) (string, string, string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(fmt.Sprintf("%s://%s:%d/", scheme, host, port))
	if err != nil {
		return "", "", ""
	}
	defer response.Body.Close()
	banner := response.Header.Get("Server")
	if powered := response.Header.Get("X-Powered-By"); powered != "" {
		banner += " " + powered
	}
	tech, version := identify(banner)
	return clean(banner), tech, version
}

func identify(value string) (string, string) {
	for _, item := range techPatterns {
		if regexp.MustCompile(item.pattern).MatchString(value) {
			return item.name, extractVersion(value)
		}
	}
	return "", ""
}

func extractVersion(value string) string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == ' ' || r == '(' })
	for _, field := range fields {
		if strings.Count(field, ".") >= 1 && field[0] >= '0' && field[0] <= '9' {
			return field
		}
	}
	return ""
}

func serviceName(port int) string {
	names := map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http", 8443: "https", 9200: "elasticsearch", 27017: "mongodb"}
	return names[port]
}
func clean(value string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, value))
}
func unique(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func writeResult(result Result, started time.Time) {
	result.DurationMS = time.Since(started).Milliseconds()
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
