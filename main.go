package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// List of WAF/CDN providers to detect
var cdnProviders = []string{
	"akamai",
	"imperva",
	"cloudflare",
	"fastly",
	"verizon",
	"stackpath",
	"incapsula",
}

// randomUserAgent generates a simple random User-Agent string
func randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"Mozilla/5.0 (X11; Linux x86_64)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)",
		"Mozilla/5.0 (Linux; Android 10)",
	}
	rand.Seed(time.Now().UnixNano())
	return agents[rand.Intn(len(agents))]
}

// checkDNS uses the "host" and "dig" commands to detect if a domain is behind a WAF/CDN.
// Returns true if CDN/WAF is detected (i.e., should be filtered out), otherwise false.
func checkDNS(domain string, verbose bool) bool {
	// "host" command
	outputHost, err := exec.Command("host", domain).CombinedOutput()
	if err == nil {
		hostString := strings.ToLower(string(outputHost))
		for _, provider := range cdnProviders {
			if strings.Contains(hostString, provider) {
				if verbose {
					fmt.Printf("%s (CDN detected via DNS 'host': %s)\n", domain, strings.Title(provider))
				}
				return true // CDN detected
			}
		}
	}

	// "dig" command
	outputDig, err := exec.Command("dig", domain).CombinedOutput()
	if err == nil {
		digString := strings.ToLower(string(outputDig))
		for _, provider := range cdnProviders {
			if strings.Contains(digString, provider) {
				if verbose {
					fmt.Printf("%s (CDN detected via DNS 'dig': %s)\n", domain, strings.Title(provider))
				}
				return true
			}
		}
	}

	return false
}

// checkHTTP makes an HTTP request and checks the "Server" and "X-CDN" headers.
// Returns true if a CDN is detected, otherwise false.
func checkHTTP(domain string, verbose bool) bool {
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	url := "http://" + domain
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		// Failed to create a request; assume not detected
		return false
	}
	req.Header.Set("User-Agent", randomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		// Connection error or timeout; not necessarily behind WAF
		return false
	}
	defer resp.Body.Close()

	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	xcdnHeader := strings.ToLower(resp.Header.Get("X-CDN"))

	for _, provider := range cdnProviders {
		if strings.Contains(serverHeader, provider) || strings.Contains(xcdnHeader, provider) {
			if verbose {
				fmt.Printf("%s (CDN detected via HTTP: %s)\n", domain, strings.Title(provider))
			}
			return true
		}
	}

	return false
}

// processDomain is the main check flow: DNS -> HTTP.
// Returns true if the domain is "clean" (not behind WAF/CDN), or false if it should be filtered out.
func processDomain(domain string, verbose bool) bool {
	// Remove any ":port" part if present
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	// First check DNS
	if checkDNS(domain, verbose) {
		return false
	}

	// If not detected via DNS, check HTTP
	if checkHTTP(domain, verbose) {
		return false
	}

	// If we reach here, no WAF/CDN was detected
	return true
}

// readDomains reads domains either from a file, a single target, or stdin
func readDomains(listFile, target string) ([]string, error) {
	var domains []string

	switch {
	case listFile != "":
		f, err := os.Open(listFile)
		if err != nil {
			return nil, fmt.Errorf("error opening file: %v", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				domains = append(domains, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}

	case target != "":
		domains = []string{target}

	default:
		// Read from stdin
		info, err := os.Stdin.Stat()
		if err != nil {
			return nil, err
		}
		if (info.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no input from file, list, target or stdin")
		}

		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return nil, err
			}
			line = strings.TrimSpace(line)
			if line != "" {
				domains = append(domains, line)
			}
			if err == io.EOF {
				break
			}
		}
	}

	return domains, nil
}

func main() {
	var (
		listFile     string
		singleTarget string
		concurrency  int
		verbose      bool
	)

	flag.StringVar(&listFile, "l", "", "File containing the list of domains")
	flag.StringVar(&singleTarget, "t", "", "Single domain to check")
	flag.IntVar(&concurrency, "c", 10, "Number of threads (goroutines) for parallel execution")
	flag.BoolVar(&verbose, "v", false, "Enable verbose mode (show WAF/CDN detections)")
	flag.Parse()

	// Read domains from file, target, or stdin
	domains, err := readDomains(listFile, singleTarget)
	if err != nil {
		log.Fatalf("Error reading domains: %v\n", err)
	}

	// Channel to queue the domains
	domainChan := make(chan string)
	var wg sync.WaitGroup

	// Create worker goroutines
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range domainChan {
				if processDomain(d, verbose) {
					// If not behind CDN, print it
					fmt.Println(d)
				}
			}
		}()
	}

	// Send domains to the channel
	go func() {
		for _, d := range domains {
			domainChan <- d
		}
		close(domainChan)
	}()

	// Wait for all workers to finish
	wg.Wait()
}
