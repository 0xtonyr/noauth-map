package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func newNeo4jDriver(ctx context.Context, password string) (neo4j.DriverWithContext, error) {
	return neo4j.NewDriverWithContext("neo4j://localhost", neo4j.BasicAuth("neo4j", password, ""))
}

func neo4jTest(ctx context.Context, driver neo4j.DriverWithContext) error {
	return driver.VerifyConnectivity(ctx)
}

func createConstraints(ctx context.Context, driver neo4j.DriverWithContext) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for _, q := range []string{
		"CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (ip:IP) REQUIRE ip.address IS UNIQUE",
		"CREATE CONSTRAINT req_id IF NOT EXISTS FOR (req:Request) REQUIRE req.id IS UNIQUE",
	} {
		query := q
		if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			return tx.Run(ctx, query, nil)
		}); err != nil {
			return err
		}
	}
	return nil
}

func insertIPsIntoNeo4j(ctx context.Context, driver neo4j.DriverWithContext, ips map[string]int) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for ip, count := range ips {
		ip, count := ip, count
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			cypher := "MERGE (ip:IP {address: $ip}) ON CREATE SET ip.count = $count, ip.lastSeen = datetime() ON MATCH SET ip.count = ip.count + $count, ip.lastSeen = datetime()"
			return tx.Run(ctx, cypher, map[string]any{"ip": ip, "count": count})
		})
		if err != nil {
			return fmt.Errorf("failed to insert/update IP %s: %w", ip, err)
		}
	}
	return nil
}

func insertRequestsFromResultFile(ctx context.Context, driver neo4j.DriverWithContext, resultFilePath string) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	file, err := os.Open(resultFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var currentRequest []string

	processRequest := func() {
		if len(currentRequest) == 0 {
			return
		}
		requestData := strings.Join(currentRequest, "\n")

		sum := sha256.Sum256([]byte(requestData))
		requestID := hex.EncodeToString(sum[:])

		var ip, endpoint string
		for _, line := range currentRequest {
			for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
				if strings.HasPrefix(line, method) {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						endpoint = parts[1]
					}
					break
				}
			}
			if endpoint != "" {
				break
			}
		}
		for _, line := range currentRequest {
			if host := extractHostFromHeader(line); host != "" {
				ip = host
				break
			}
		}

		id, content, ep, ipAddr := requestID, requestData, endpoint, ip
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			cypher := `
				MERGE (ip:IP {address: $ip})
				MERGE (req:Request {id: $id}) ON CREATE SET req.content = $content, req.endpoint = $endpoint
				MERGE (req)-[:REQUEST_TO]->(ip)
			`
			return tx.Run(ctx, cypher, map[string]any{
				"id":       id,
				"content":  content,
				"endpoint": ep,
				"ip":       ipAddr,
			})
		})
		if err != nil {
			fmt.Printf("Failed to insert/update Request %s in Neo4j: %s\n", requestID[:8], err)
		}
		currentRequest = currentRequest[:0]
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "==============================" {
			processRequest()
		} else {
			currentRequest = append(currentRequest, line)
		}
	}
	processRequest()

	return scanner.Err()
}
