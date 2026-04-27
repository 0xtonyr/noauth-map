package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func parsePCAP(filePath string, resultFileName string) {
	startTime := time.Now()
	fmt.Printf("[+] Parsing %s file\n", filePath)

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var nonAuthenticatedRequests []string

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload := appLayer.Payload()
				if strings.Contains(string(payload), "HTTP") {
					nonAuthenticatedRequests = append(nonAuthenticatedRequests, string(payload))
				}
			}
		}
	}

	filteredRequests := filterNonAuthenticatedRequests(nonAuthenticatedRequests)
	saveResults(filteredRequests, resultFileName)

	fmt.Printf("[+] Scan completed in %.3fs\n", time.Since(startTime).Seconds())
}

func filterNonAuthenticatedRequests(requests []string) []string {
	var nonAuthenticatedRequests []string

	for _, req := range requests {
		lower := strings.ToLower(req)
		if !strings.Contains(lower, "proxy-authorization") &&
			!strings.Contains(lower, "x-auth-token") &&
			!strings.Contains(lower, "x-api-key") &&
			!strings.Contains(lower, "authorization") &&
			!strings.Contains(lower, "cookie") {
			nonAuthenticatedRequests = append(nonAuthenticatedRequests, req)
		}
	}

	return nonAuthenticatedRequests
}

func saveResults(requests []string, filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for i, req := range requests {
		fmt.Fprintf(w, "==============================\n")
		fmt.Fprintf(w, "Packet number: %d\n", i+1)
		fmt.Fprintf(w, "%s\n", req)
	}
	if err := w.Flush(); err != nil {
		log.Fatalf("Failed to flush results file: %v", err)
	}
}

// extractHostFromHeader returns the Host header value from a single HTTP header line.
// Handles IP:port, bare IP, and hostnames.
func extractHostFromHeader(line string) string {
	if !strings.HasPrefix(strings.ToLower(line), "host:") {
		return ""
	}
	return strings.TrimSpace(line[5:])
}

func countIPsInResultFile(resultFilePath string) (map[string]int, error) {
	file, err := os.Open(resultFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	ipCounter := make(map[string]int)
	for scanner.Scan() {
		if ip := extractHostFromHeader(scanner.Text()); ip != "" {
			ipCounter[ip]++
		}
	}

	return ipCounter, scanner.Err()
}

func main() {
	neo4jPasswordFlag := flag.String("neo4jpassword", "", "Neo4j password (deprecated: use NEO4J_PASSWORD env var)")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: ./noauth-map <arquivo.pcap>")
		fmt.Fprintln(os.Stderr, "       NEO4J_PASSWORD=<senha> ./noauth-map <arquivo.pcap>")
		os.Exit(1)
	}

	neo4jPassword := os.Getenv("NEO4J_PASSWORD")
	if neo4jPassword == "" && *neo4jPasswordFlag != "" {
		fmt.Fprintln(os.Stderr, "[!] Warning: -neo4jpassword exposes credentials in the process list. Use NEO4J_PASSWORD env var instead.")
		neo4jPassword = *neo4jPasswordFlag
	}
	if neo4jPassword == "" {
		fmt.Fprintln(os.Stderr, "[-] Neo4j password required: set NEO4J_PASSWORD env var or use -neo4jpassword flag.")
		os.Exit(1)
	}

	filePath := args[0]
	baseName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	resultFileName := fmt.Sprintf("%s-analysis.txt", baseName)

	parsePCAP(filePath, resultFileName)

	ctx := context.Background()

	fmt.Println("[+] Starting Neo4j connection test...")
	driver, err := newNeo4jDriver(ctx, neo4jPassword)
	if err != nil {
		fmt.Printf("[-] Failed to create Neo4j driver: %v\n", err)
		os.Exit(1)
	}
	defer driver.Close(ctx)

	if err := neo4jTest(ctx, driver); err != nil {
		fmt.Printf("[-] Neo4j connection test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Neo4j connection test succeeded.")

	if err := createConstraints(ctx, driver); err != nil {
		fmt.Printf("[-] Failed to create Neo4j constraints: %v\n", err)
		os.Exit(1)
	}

	ipCounter, err := countIPsInResultFile(resultFileName)
	if err != nil {
		log.Fatalf("Error counting IPs in the results file: %v", err)
	}

	if err := insertIPsIntoNeo4j(ctx, driver, ipCounter); err != nil {
		fmt.Printf("[-] Failed to insert/update IPs in Neo4j: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] IPs successfully inserted into Neo4j.")

	fmt.Println("[+] Starting to insert requests and link them to IPs...")
	if err := insertRequestsFromResultFile(ctx, driver, resultFileName); err != nil {
		fmt.Printf("[-] Failed to insert requests in Neo4j: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Requests successfully inserted and linked to IPs in Neo4j.")
}
