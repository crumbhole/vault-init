// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// Modifications Copyright 2021 Liatrio

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"time"
)

var (
	vaultAddr  string
	httpClient *http.Client

	vaultSecretShares      int
	vaultSecretThreshold   int
	vaultStoredShares      int
	vaultRecoveryShares    int
	vaultRecoveryThreshold int

	k8sClient     *kubernetes.Clientset
	k8sSecretName string
	k8sNamespace  string
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

	var err error

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

	k8sSecretName = os.Getenv("K8S_SECRET_NAME")
	if k8sSecretName == "" {
		log.Fatal("K8S_SECRET_NAME must be set and not empty")
	}

	var clusterConfig *rest.Config
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
			response.Body.Close()
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

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()

	initRequestResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != http.StatusOK {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	secret, err := k8sClient.CoreV1().Secrets(k8sNamespace).Get(ctx, k8sSecretName, metav1.GetOptions{})
	switch {
	case err != nil && errors.IsNotFound(err): // secret doesn't exist, we need to create
		_, err = k8sClient.CoreV1().Secrets(k8sNamespace).Create(ctx, &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      k8sSecretName,
				Namespace: k8sNamespace,
			},
			Data: map[string][]byte{
				"rootToken":  []byte(initResponse.RootToken),
				"unsealKeys": initRequestResponseBody,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			log.Println(err)
			return
		}
	case err == nil: // secret exists, we need to update
		secret.Data["rootToken"] = []byte(initResponse.RootToken)
		secret.Data["unsealKeys"] = initRequestResponseBody

		_, err = k8sClient.CoreV1().Secrets(k8sNamespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			log.Println(err)
			return
		}
	default:
		log.Println(err)
		return
	}

	log.Printf("Root token written to secret %s/%s", k8sNamespace, k8sSecretName)

	log.Println("Initialization complete.")
}

func unseal(ctx context.Context) {
	secret, err := k8sClient.CoreV1().Secrets(k8sNamespace).Get(ctx, k8sSecretName, metav1.GetOptions{})
	if err != nil {
		log.Println(err)
		return
	}

	var initResponse InitResponse

	unsealKeysPlaintext, ok := secret.Data["unsealKeys"]
	if !ok {
		log.Printf("secret %s/%s does not contain unseal keys\n", k8sNamespace, k8sSecretName)
		return
	}

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
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

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

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

func processTLSConfig(cfg *tls.Config, serverName, caCert, caPath string) error {
	cfg.ServerName = serverName

	// If a CA cert is provided, trust only that cert
	if caCert != "" {
		b, err := os.ReadFile(caCert)
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
	if r >= '0' || r <= '9' {
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
