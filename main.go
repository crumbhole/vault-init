// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// Modifications Copyright 2021 Liatrio

// Package main implements the vault-init service for initializing and unsealing Vault.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	vaultAddr  string
	httpClient *http.Client

	vaultSecretShares      int
	vaultSecretThreshold   int
	vaultStoredShares      int
	vaultRecoveryShares    int
	vaultRecoveryThreshold int

	secretDir      string
	ageRecipients  []age.Recipient
	secretFilePath string

	k8sClient              *kubernetes.Clientset
	k8sNamespace           string
	ageIdentitiesSecretName string
	ageIdentitiesSecretKey  string
)

// InitRequest holds a Vault init request.
type InitRequest struct {
	SecretShares      int `json:"secret_shares"`
	SecretThreshold   int `json:"secret_threshold"`
	StoredShares      int `json:"stored_shares"`
	RecoveryShares    int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

// UnsealRequest holds a Vault unseal request.
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse holds a Vault unseal response.
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

func main() {
	ctx := context.Background()
	log.Println("Starting the vault-init service...")

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	vaultSecretShares = intFromEnv("VAULT_SECRET_SHARES", 5)
	vaultSecretThreshold = intFromEnv("VAULT_SECRET_THRESHOLD", 3)

	vaultInsecureSkipVerify := boolFromEnv("VAULT_SKIP_VERIFY", false)

	vaultAutoUnseal := boolFromEnv("VAULT_AUTO_UNSEAL", true)

	if vaultAutoUnseal {
		vaultStoredShares = intFromEnv("VAULT_STORED_SHARES", 1)
		vaultRecoveryShares = intFromEnv("VAULT_RECOVERY_SHARES", 1)
		vaultRecoveryThreshold = intFromEnv("VAULT_RECOVERY_THRESHOLD", 1)
	}

	vaultCaCert := stringFromEnv("VAULT_CACERT", "")
	vaultCaPath := stringFromEnv("VAULT_CAPATH", "")

	vaultClientTimeout := durFromEnv("VAULT_CLIENT_TIMEOUT", 60*time.Second)

	vaultServerName := stringFromEnv("VAULT_TLS_SERVER_NAME", "")

	checkInterval := durFromEnv("CHECK_INTERVAL", 10*time.Second)

	// Get secret directory from environment
	secretDir = os.Getenv("SECRET_DIR")
	if secretDir == "" {
		log.Fatal("SECRET_DIR must be set and not empty")
	}

	// Get age recipients from environment
	recipientsStr := os.Getenv("AGE_RECIPIENTS")
	if recipientsStr == "" {
		log.Fatal("AGE_RECIPIENTS must be set and not empty")
	}

	// Parse age recipients (comma-separated list of public keys)
	recipientsList := strings.Split(recipientsStr, ",")
	ageRecipients = make([]age.Recipient, 0, len(recipientsList))
	for _, recipientStr := range recipientsList {
		recipientStr = strings.TrimSpace(recipientStr)
		if recipientStr == "" {
			continue
		}
		recipient, err := age.ParseX25519Recipient(recipientStr)
		if err != nil {
			log.Fatalf("failed to parse age recipient %q: %v", recipientStr, err)
		}
		ageRecipients = append(ageRecipients, recipient)
	}

	if len(ageRecipients) == 0 {
		log.Fatal("at least one valid age recipient must be provided")
	}

	// Get Kubernetes secret name for AGE_IDENTITIES (required)
	ageIdentitiesSecretName = os.Getenv("AGE_IDENTITIES_SECRET_NAME")
	if ageIdentitiesSecretName == "" {
		log.Fatal("AGE_IDENTITIES_SECRET_NAME must be set and not empty")
	}

	ageIdentitiesSecretKey = os.Getenv("AGE_IDENTITIES_SECRET_KEY")
	if ageIdentitiesSecretKey == "" {
		ageIdentitiesSecretKey = "identities" // default key name
	}

	// Initialize Kubernetes client
	var clusterConfig *rest.Config
	var err error
	clusterConfig, err = rest.InClusterConfig()
	if err != nil {
		log.Fatalf("error fetching cluster config: %v", err)
	}

	k8sClient, err = kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		log.Fatalf("error creating kubernetes client: %v", err)
	}

	k8sNamespace, err = getCurrentNamespace()
	if err != nil {
		log.Fatalf("error getting current namespace: %v", err)
	}

	log.Printf("Will read AGE_IDENTITIES from secret %s/%s (key: %s)", k8sNamespace, ageIdentitiesSecretName, ageIdentitiesSecretKey)

	// Ensure secret directory exists
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		log.Fatalf("failed to create secret directory: %v", err)
	}

	secretFilePath = filepath.Join(secretDir, "vault-secrets.age")

	tlsConfig := &tls.Config{
		//#nosec G402: Yes, this is insecure
		InsecureSkipVerify: vaultInsecureSkipVerify,
	}
	if err := processTLSConfig(tlsConfig, vaultServerName, vaultCaCert, vaultCaPath); err != nil {
		log.Fatal(err)
	}

	httpClient = &http.Client{
		Timeout: vaultClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	runner(ctx, checkInterval, vaultAutoUnseal)
}

func runner(ctx context.Context, checkInterval time.Duration, vaultAutoUnseal bool) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	stop := func() {
		log.Printf("Shutting down")
		os.Exit(0)
	}

	for {
		select {
		case <-signalCh:
			stop()
		default:
		}
		response, err := httpClient.Head(vaultAddr + "/v1/sys/health")

		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}

		if err != nil {
			log.Println(err)
			time.Sleep(checkInterval)
			continue
		}

		handleResponseCode(ctx, response.StatusCode, vaultAutoUnseal)

		if checkInterval <= 0 {
			log.Printf("Check interval set to less than 0, exiting.")
			stop()
		}

		log.Printf("Next check in %s", checkInterval)

		select {
		case <-signalCh:
			stop()
		case <-time.After(checkInterval):
		}
	}
}

func handleResponseCode(ctx context.Context, code int, vaultAutoUnseal bool) {
	switch code {
	case http.StatusOK:
		log.Println("Vault is initialized and unsealed.")
	case http.StatusTooManyRequests:
		log.Println("Vault is unsealed and in standby mode.")
	case http.StatusNotImplemented:
		log.Println("Vault is not initialized.")
		log.Println("Initializing...")
		initialize(ctx)
		if !vaultAutoUnseal {
			log.Println("Unsealing...")
			unseal(ctx)
		}
	case http.StatusServiceUnavailable:
		log.Println("Vault is sealed.")
		if !vaultAutoUnseal {
			log.Println("Unsealing...")
			unseal(ctx)
		}
	default:
		log.Printf("Vault is in an unknown state. Status code: %d", code)
	}
}

func initialize(ctx context.Context) {
	initRequest := InitRequest{
		SecretShares:      vaultSecretShares,
		SecretThreshold:   vaultSecretThreshold,
		StoredShares:      vaultStoredShares,
		RecoveryShares:    vaultRecoveryShares,
		RecoveryThreshold: vaultRecoveryThreshold,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, vaultAddr+"/v1/sys/init", r)
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request) //nolint:gosec // URL is constructed from trusted config
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = response.Body.Close() }()

	initRequestResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != http.StatusOK {
		log.Printf("init: non 200 status code: %d", response.StatusCode) //nolint:gosec // status code is an int, not tainted
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token with age...")

	// Encrypt and save to filesystem
	if err := encryptAndSaveSecrets(initRequestResponseBody); err != nil {
		log.Printf("failed to encrypt and save secrets: %v", err)
		return
	}

	log.Printf("Root token and unseal keys written to %s", secretFilePath)
	log.Println("Initialization complete.")
}

func unseal(ctx context.Context) {
	// Read and decrypt secrets from filesystem
	initRequestResponseBody, err := readAndDecryptSecrets(ctx)
	if err != nil {
		log.Printf("failed to read and decrypt secrets: %v", err)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(ctx, key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(ctx context.Context, key string) (bool, error) {
	unsealRequest := UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, vaultAddr+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request) //nolint:gosec // URL is constructed from trusted config
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unseal: non-200 status code: %d", response.StatusCode)
	}

	unsealRequestResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}

// encryptAndSaveSecrets encrypts the vault secrets using age and saves them to the filesystem
func encryptAndSaveSecrets(data []byte) error {
	// Create a temporary file for atomic write
	tmpFile := secretFilePath + ".tmp"

	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpFile)
	}()

	// Create age writer
	w, err := age.Encrypt(f, ageRecipients...)
	if err != nil {
		return fmt.Errorf("failed to create age encryptor: %w", err)
	}

	// Write encrypted data
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	// Close the age writer to finalize encryption
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close age writer: %w", err)
	}

	// Close the file
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomically rename temp file to final location
	if err := os.Rename(tmpFile, secretFilePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// getAgeIdentities retrieves age identities from Kubernetes secret
func getAgeIdentities(ctx context.Context) ([]age.Identity, error) {
	// Get from Kubernetes secret
	secret, err := k8sClient.CoreV1().Secrets(k8sNamespace).Get(ctx, ageIdentitiesSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", k8sNamespace, ageIdentitiesSecretName, err)
	}

	identitiesBytes, ok := secret.Data[ageIdentitiesSecretKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not contain key %q", k8sNamespace, ageIdentitiesSecretName, ageIdentitiesSecretKey)
	}

	identitiesStr := string(identitiesBytes)
	log.Printf("Retrieved AGE_IDENTITIES from secret %s/%s", k8sNamespace, ageIdentitiesSecretName)

	// Parse age identities (comma-separated list of private keys)
	identitiesList := strings.Split(identitiesStr, ",")
	identities := make([]age.Identity, 0, len(identitiesList))
	for _, identityStr := range identitiesList {
		identityStr = strings.TrimSpace(identityStr)
		if identityStr == "" {
			continue
		}
		identity, err := age.ParseX25519Identity(identityStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse age identity: %w", err)
		}
		identities = append(identities, identity)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one valid age identity must be provided")
	}

	return identities, nil
}

// readAndDecryptSecrets reads and decrypts the vault secrets from the filesystem
func readAndDecryptSecrets(ctx context.Context) ([]byte, error) {
	// Check if file exists
	if _, err := os.Stat(secretFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("secrets file does not exist: %s", secretFilePath)
	}

	// Read encrypted file
	encryptedData, err := os.ReadFile(secretFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets file: %w", err)
	}

	// Get age identities
	identities, err := getAgeIdentities(ctx)
	if err != nil {
		return nil, err
	}

	// Decrypt data
	r, err := age.Decrypt(bytes.NewReader(encryptedData), identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secrets: %w", err)
	}

	decryptedData, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return decryptedData, nil
}

func processTLSConfig(cfg *tls.Config, serverName, caCert, caPath string) error {
	cfg.ServerName = serverName

	// If a CA cert is provided, trust only that cert
	if caCert != "" {
		b, err := os.ReadFile(caCert) //nolint:gosec // path comes from trusted env config
		if err != nil {
			return fmt.Errorf("failed to read CA cert: %w", err)
		}

		root := x509.NewCertPool()
		if ok := root.AppendCertsFromPEM(b); !ok {
			return fmt.Errorf("failed to parse CA cert")
		}

		cfg.RootCAs = root
		return nil
	}

	// If a directory is provided, trust only the certs in that directory
	if caPath != "" {
		files, err := os.ReadDir(caPath)
		if err != nil {
			return fmt.Errorf("failed to read CA path: %w", err)
		}

		root := x509.NewCertPool()

		for _, f := range files {
			b, err := os.ReadFile(f.Name())
			if err != nil {
				return fmt.Errorf("failed to read cert: %w", err)
			}
			if ok := root.AppendCertsFromPEM(b); !ok {
				return fmt.Errorf("failed to parse cert")
			}
		}

		cfg.RootCAs = root
		return nil
	}

	return nil
}

func boolFromEnv(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return b
}

func intFromEnv(env string, def int) int {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return i
}

func stringFromEnv(env string, def string) string {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	return val
}

func durFromEnv(env string, def time.Duration) time.Duration {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	r := val[len(val)-1]
	if r >= '0' && r <= '9' {
		val += "s" // assume seconds
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return d
}

func getCurrentNamespace() (string, error) {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", err
	}

	return string(b), nil
}
