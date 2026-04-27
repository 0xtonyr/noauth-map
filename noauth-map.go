package main

import (
	"bufio"
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

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	fmt.Printf("[+] Scan completed in %.3fs\n", duration.Seconds())
}

func filterNonAuthenticatedRequests(requests []string) []string {
	var nonAuthenticatedRequests []string

	for _, req := range requests {
		if !strings.Contains(req, "Proxy-Authorization") &&
			!strings.Contains(req, "x-auth-token") &&
			!strings.Contains(req, "x-api-key") &&
			!strings.Contains(req, "Authorization") &&
			!strings.Contains(req, "Cookie") {
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

	for i, req := range requests {
		file.WriteString("==============================\n")
		file.WriteString(fmt.Sprintf("Packet number: %d\n", i+1))
		file.WriteString(req + "\n")
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
	var hostIPs []string

	for scanner.Scan() {
		request := scanner.Text()
		ip := extractHostFromHeader(request)
		if ip != "" {
			hostIPs = append(hostIPs, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	ipCounter := make(map[string]int)
	for _, ip := range hostIPs {
		ipCounter[ip]++
	}
	return ipCounter, nil
}


func main() {
	neo4jPasswordFlag := flag.String("neo4jpassword", "", "Neo4j password (deprecated: use NEO4J_PASSWORD env var)")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: ./http-filter <arquivo.pcap>")
		fmt.Fprintln(os.Stderr, "       NEO4J_PASSWORD=<senha> ./http-filter <arquivo.pcap>")
		os.Exit(1)
	}

	// Prefer env var; fall back to flag with a warning so credentials stay off the process list.
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

	fmt.Println("[+] Starting Neo4j connection test...")
	if err := neo4jTest(neo4jPassword); err != nil {
		fmt.Printf("[-] Neo4j connection test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Neo4j connection test succeeded.")

	ipCounter, err := countIPsInResultFile(resultFileName)
	if err != nil {
		log.Fatalf("Error counting IPs in the results file: %v", err)
	}

	if err := insertIPsIntoNeo4j(ipCounter, neo4jPassword); err != nil {
		fmt.Printf("[-] Failed to insert/update IPs in Neo4j: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] IPs successfully inserted into Neo4j.")

	fmt.Println("[+] Starting to insert requests and link them to IPs...")
	if err := insertRequestsFromResultFile(resultFileName, neo4jPassword); err != nil {
		fmt.Printf("[-] Failed to insert requests in Neo4j: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Requests successfully inserted and linked to IPs in Neo4j.")
}
