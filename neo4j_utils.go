package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Função para testar a conexão com o banco de dados Neo4j
func neo4jTest(password string) error {
	ctx := context.Background()
	dbUri := "neo4j://localhost"
	dbUser := "neo4j"
	// dbPassword agora é obtido do argumento da função
	dbPassword := password
	driver, err := neo4j.NewDriverWithContext(dbUri, neo4j.BasicAuth(dbUser, dbPassword, ""))
	if err != nil {
		return err
	}
	defer driver.Close(ctx)

	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		return err
	}

	return nil
}

// Insere IPs no Neo4j
func insertIPsIntoNeo4j(ips map[string]int, password string) error {
	dbUri := "neo4j://localhost"
	dbUser := "neo4j"
	// dbPassword agora é obtido do argumento da função
	dbPassword := password

	driver, err := neo4j.NewDriver(dbUri, neo4j.BasicAuth(dbUser, dbPassword, ""), func(config *neo4j.Config) {
		config.MaxConnectionLifetime = time.Hour
	})
	if err != nil {
		return fmt.Errorf("Error in Neo4j, something went wrong: %w", err)
	}
	defer driver.Close()

	session := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	for ip, count := range ips {
		_, err := session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
			cypher := "MERGE (ip:IP {address: $ip}) ON CREATE SET ip.count = $count, ip.lastSeen = datetime() ON MATCH SET ip.count = ip.count + $count, ip.lastSeen = datetime()"
			params := map[string]interface{}{
				"ip":    ip,
				"count": count,
			}
			return transaction.Run(cypher, params)
		})

		if err != nil {
			return fmt.Errorf("Failed to insert/update IPs: %s in Neo4j: %w", ip, err)
		}
	}

	return nil
}

func insertRequestsFromResultFile(resultFilePath string, password string) error {
	dbUri := "neo4j://localhost"
	dbUser := "neo4j"
	dbPassword := password

	driver, err := neo4j.NewDriver(dbUri, neo4j.BasicAuth(dbUser, dbPassword, ""), func(config *neo4j.Config) {
		config.MaxConnectionLifetime = time.Hour
	})
	if err != nil {
		return fmt.Errorf("Error in Neo4j, something went wrong: %w", err)
	}
	defer driver.Close()

	session := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	file, err := os.Open(resultFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentRequest []string

	processRequest := func() {
		if len(currentRequest) == 0 {
			return
		}
		requestData := strings.Join(currentRequest, "\n")

		// SHA256 of content as stable, collision-free ID across re-runs.
		sum := sha256.Sum256([]byte(requestData))
		requestID := hex.EncodeToString(sum[:])

		var ip, endpoint string
		parts := strings.Fields(currentRequest[0])
		if len(parts) > 1 {
			endpoint = parts[1]
		}
		for _, line := range currentRequest {
			if host := extractHostFromHeader(line); host != "" {
				ip = host
				break
			}
		}

		_, err := session.WriteTransaction(func(transaction neo4j.Transaction) (interface{}, error) {
			cypher := `
                MERGE (ip:IP {address: $ip})
                MERGE (req:Request {id: $id}) ON CREATE SET req.content = $content, req.endpoint = $endpoint
                MERGE (req)-[:REQUEST_TO]->(ip)
                `
			params := map[string]interface{}{
				"id":       requestID,
				"content":  requestData,
				"endpoint": endpoint,
				"ip":       ip,
			}
			return transaction.Run(cypher, params)
		})

		if err != nil {
			fmt.Printf("Failed to insert/update Request %s in Neo4j: %s\n", requestID[:8], err)
		}
		currentRequest = []string{}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "==============================" {
			processRequest() // Processa a requisição atual
		} else {
			currentRequest = append(currentRequest, line) // Acumula linhas da requisição atual
		}
	}
	processRequest() // Assegura que a última requisição seja processada

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
