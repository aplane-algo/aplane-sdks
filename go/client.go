// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignerClient is the client for connecting to apsigner.
type SignerClient struct {
	baseURL   string
	token     string
	client    *http.Client
	sshTunnel *sshTunnel
	keyMu     sync.RWMutex
	keyCache  map[string]*KeyInfo
}

// NewSignerClientWithToken creates a signer client for an already-known base URL.
// This is useful when the caller owns the transport or tunnel lifecycle.
func NewSignerClientWithToken(baseURL, token string) *SignerClient {
	return &SignerClient{
		baseURL:  baseURL,
		token:    token,
		client:   &http.Client{Timeout: time.Duration(DefaultTimeout) * time.Second},
		keyCache: nil,
	}
}

// SetHTTPClient overrides the HTTP client used for requests.
func (c *SignerClient) SetHTTPClient(client *http.Client) {
	if client != nil {
		c.client = client
	}
}

func readErrorBody(resp *http.Response) string {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("<failed to read error body: %v>", err)
	}
	return string(body)
}

// ConnectSSH creates a client connected via SSH tunnel.
func ConnectSSH(host, token, sshKeyPath string, opts *SSHConnectOptions) (*SignerClient, error) {
	sshPort := DefaultSSHPort
	signerPort := DefaultSignerPort
	timeout := DefaultTimeout

	var knownHostsPath string

	if opts != nil {
		if opts.SSHPort > 0 {
			sshPort = opts.SSHPort
		}
		if opts.SignerPort > 0 {
			signerPort = opts.SignerPort
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		if opts.KnownHostsPath != "" {
			knownHostsPath = opts.KnownHostsPath
		}
	}

	trustOnFirstUse := opts != nil && opts.TrustOnFirstUse
	tunnel := &sshTunnel{knownHostsPath: knownHostsPath, trustOnFirstUse: trustOnFirstUse}
	localPort, err := tunnel.connect(host, sshPort, signerPort, token, ExpandPath(sshKeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH tunnel: %w", err)
	}

	return &SignerClient{
		baseURL:   fmt.Sprintf("http://localhost:%d", localPort),
		token:     token,
		client:    &http.Client{Timeout: time.Duration(timeout) * time.Second},
		sshTunnel: tunnel,
	}, nil
}

// FromEnv creates a client from environment configuration.
// Reads token from dataDir/aplane.token and config from dataDir/config.yaml.
// If config contains SSH settings, connects via SSH tunnel.
func FromEnv(opts *FromEnvOptions) (*SignerClient, error) {
	dataDir := ""
	timeout := DefaultTimeout

	if opts != nil {
		if opts.DataDir != "" {
			dataDir = opts.DataDir
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	dataDir, err := ResolveDataDir(dataDir)
	if err != nil {
		return nil, err
	}

	// Load token
	token, err := LoadTokenFromDir(dataDir)
	if err != nil {
		return nil, err
	}

	// Load config
	config, err := LoadConfig(dataDir)
	if err != nil {
		return nil, err
	}

	// SSH is required
	if config.SSH == nil || config.SSH.Host == "" {
		return nil, fmt.Errorf("no ssh block in config.yaml; add an ssh block with host, port, and identity_file")
	}

	sshKeyPath := ResolvePath(config.SSH.IdentityFile, dataDir)
	knownHostsPath := ResolvePath(config.SSH.KnownHostsPath, dataDir)
	return ConnectSSH(config.SSH.Host, token, sshKeyPath, &SSHConnectOptions{
		SSHPort:         config.SSH.Port,
		SignerPort:      config.SignerPort,
		Timeout:         timeout,
		KnownHostsPath:  knownHostsPath,
		TrustOnFirstUse: config.SSH.TrustOnFirstUse,
	})
}

// Close closes the client and any SSH tunnel.
func (c *SignerClient) Close() {
	if c.sshTunnel != nil {
		c.sshTunnel.close()
	}
}

// Health checks if the signer is reachable.
func (c *SignerClient) Health() (bool, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/health", nil)
	if err != nil {
		return false, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, nil // Not reachable
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200, nil
}

// ListKeys returns all available signing keys.
func (c *SignerClient) ListKeys(refresh bool) ([]KeyInfo, error) {
	if !refresh {
		if keys := c.cachedKeys(); keys != nil {
			return keys, nil
		}
	}

	keysResp, err := c.GetKeysResponseWithContext(context.Background())
	if err != nil {
		if err == ErrSignerLocked || err == ErrAuthentication {
			return nil, err
		}
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	if keysResp.Locked {
		return nil, ErrSignerLocked
	}
	return keysResp.Keys, nil
}

// GetKeyInfo returns info for a specific key address.
func (c *SignerClient) GetKeyInfo(address string) (*KeyInfo, error) {
	c.keyMu.RLock()
	if c.keyCache != nil {
		if k, ok := c.keyCache[address]; ok {
			c.keyMu.RUnlock()
			return k, nil
		}
	}
	c.keyMu.RUnlock()

	if _, err := c.ListKeys(true); err != nil {
		return nil, err
	}

	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	if k, ok := c.keyCache[address]; ok {
		return k, nil
	}
	return nil, ErrKeyNotFound
}

func (c *SignerClient) cachedKeys() []KeyInfo {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	if c.keyCache == nil {
		return nil
	}
	keys := make([]KeyInfo, 0, len(c.keyCache))
	for _, k := range c.keyCache {
		keys = append(keys, *k)
	}
	return keys
}

// GetKeysResponseWithContext fetches /keys with raw locked-state reporting.
func (c *SignerClient) GetKeysResponseWithContext(ctx context.Context) (*KeysResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return &KeysResponse{Locked: true}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var keysResp keysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	cache := make(map[string]*KeyInfo, len(keysResp.Keys))
	for i := range keysResp.Keys {
		k := &keysResp.Keys[i]
		cache[k.Address] = k
	}
	c.keyMu.Lock()
	c.keyCache = cache
	c.keyMu.Unlock()

	return &KeysResponse{
		Count: keysResp.Count,
		Keys:  keysResp.Keys,
	}, nil
}

// ListKeyTypes returns available key types and their creation parameters.
func (c *SignerClient) ListKeyTypes() ([]KeyTypeInfo, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/keytypes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list key types: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var ktResp keyTypesResponse
	if err := json.NewDecoder(resp.Body).Decode(&ktResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return ktResp.KeyTypes, nil
}

// GenerateKey generates a new key on the signer.
func (c *SignerClient) GenerateKey(keyType string, parameters map[string]string) (*GenerateResult, error) {
	genReq := generateRequest{KeyType: keyType, Parameters: parameters}
	jsonBody, err := json.Marshal(genReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/admin/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, ErrSignerLocked
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("key generation failed (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var result GenerateResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Invalidate key cache
	c.keyMu.Lock()
	c.keyCache = nil
	c.keyMu.Unlock()

	return &result, nil
}

// DeleteKey deletes a key from the signer.
func (c *SignerClient) DeleteKey(address string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/admin/keys?"+url.Values{"address": []string{address}}.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return ErrSignerLocked
	}
	if resp.StatusCode == 404 {
		return ErrKeyDeletion
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("key deletion failed (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	// Invalidate key cache
	c.keyMu.Lock()
	c.keyCache = nil
	c.keyMu.Unlock()

	return nil
}

// PlanGroup previews group building without signing or approval.
func (c *SignerClient) PlanGroup(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) (*PlanGroupResponse, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	return c.PlanRequestsWithContext(context.Background(), requests)
}

// PlanRequestsWithContext posts raw /plan requests without rebuilding them from transactions.
func (c *SignerClient) PlanRequestsWithContext(ctx context.Context, requests []SignRequest) (*PlanGroupResponse, error) {
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	groupReq := groupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/plan", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to plan group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("plan failed (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var planResp PlanGroupResponse
	if err := json.NewDecoder(resp.Body).Decode(&planResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if planResp.Error != "" {
		return nil, fmt.Errorf("plan failed: %s", planResp.Error)
	}

	return &planResp, nil
}

// SignTransaction signs a single transaction.
// Returns the signed transaction as base64.
func (c *SignerClient) SignTransaction(txn types.Transaction, authAddress string, lsigArgs LsigArgs) (string, error) {
	signed, err := c.SignTransactions([]types.Transaction{txn}, []string{authAddress}, lsigArgsToMap(authAddress, lsigArgs))
	return signed, err
}

// SignTransactions signs multiple transactions as a group.
// Returns concatenated signed transactions as base64.
func (c *SignerClient) SignTransactions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) (string, error) {
	return c.sign(buildSignRequests(txns, authAddresses, lsigArgsMap))
}

// SignTransactionsWithOptions signs transactions with passthrough support.
// Returns concatenated signed transactions as base64.
func (c *SignerClient) SignTransactionsWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) (string, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return "", err
	}
	if hasForeignRequests(requests) {
		return "", fmt.Errorf("foreign entries are only supported on /plan; use PlanGroup first, then resubmit foreign slots as passthrough")
	}
	return c.sign(requests)
}

// SignTransactionsList signs transactions and returns individual base64 strings.
func (c *SignerClient) SignTransactionsList(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) ([]string, error) {
	return c.signList(buildSignRequests(txns, authAddresses, lsigArgsMap))
}

// SignTransactionsListWithOptions signs transactions with passthrough support
// and returns individual base64 strings.
func (c *SignerClient) SignTransactionsListWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) ([]string, error) {
	requests, err := buildSignRequestsWithOptions(txns, authAddresses, lsigArgsMap, opts)
	if err != nil {
		return nil, err
	}
	if hasForeignRequests(requests) {
		return nil, fmt.Errorf("foreign entries are only supported on /plan; use PlanGroup first, then resubmit foreign slots as passthrough")
	}
	return c.signList(requests)
}

// buildSignRequestsWithOptions converts transactions into sign requests with passthrough/foreign support.
func buildSignRequestsWithOptions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap, opts *SignOptions) ([]SignRequest, error) {
	requests := make([]SignRequest, len(txns))

	for i, txn := range txns {
		// Passthrough: include pre-signed transaction as-is
		if opts != nil && opts.Passthrough != nil {
			if b64, ok := opts.Passthrough[i]; ok {
				decoded, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					return nil, fmt.Errorf("invalid passthrough transaction %d: invalid base64: %w", i+1, err)
				}
				requests[i] = SignRequest{SignedTxnHex: hex.EncodeToString(decoded)}
				continue
			}
		}

		txnBytes := encodeTxn(txn)
		txnBytesHex := hex.EncodeToString(txnBytes)

		authAddr := ""
		if i < len(authAddresses) {
			authAddr = authAddresses[i]
		}

		// Foreign mode: no auth address
		if authAddr == "" {
			req := SignRequest{TxnBytesHex: txnBytesHex}
			if opts != nil && opts.LsigSizes != nil {
				if size, ok := opts.LsigSizes[i]; ok {
					req.LsigSize = size
				}
			}
			requests[i] = req
			continue
		}

		req := SignRequest{
			AuthAddress: authAddr,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnBytesHex,
		}

		if lsigArgsMap != nil {
			if args, ok := lsigArgsMap[authAddr]; ok {
				req.LsigArgs = make(map[string]string)
				for name, value := range args {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
		}

		requests[i] = req
	}

	return requests, nil
}

func hasForeignRequests(requests []SignRequest) bool {
	for _, req := range requests {
		if req.TxnBytesHex != "" && req.AuthAddress == "" && req.SignedTxnHex == "" {
			return true
		}
	}
	return false
}

// buildSignRequests converts transactions into sign requests.
func buildSignRequests(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) []SignRequest {
	requests := make([]SignRequest, len(txns))

	for i, txn := range txns {
		txnBytes := encodeTxn(txn)
		txnBytesHex := hex.EncodeToString(txnBytes)

		authAddr := txn.Sender.String()
		if i < len(authAddresses) && authAddresses[i] != "" {
			authAddr = authAddresses[i]
		}

		req := SignRequest{
			AuthAddress: authAddr,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnBytesHex,
		}

		if lsigArgsMap != nil {
			if args, ok := lsigArgsMap[authAddr]; ok {
				req.LsigArgs = make(map[string]string)
				for name, value := range args {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
		}

		requests[i] = req
	}

	return requests
}

func validateRequests(requests []SignRequest) error {
	groupReq := groupSignRequest{Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return fmt.Errorf("invalid sign request: %w", err)
	}
	return nil
}

// SignRequestsWithContext posts raw /sign requests and returns the server response.
func (c *SignerClient) SignRequestsWithContext(ctx context.Context, requests []SignRequest) (*GroupSignResponse, error) {
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	groupReq := groupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var groupResp GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return nil, fmt.Errorf("group signing failed: %s", groupResp.Error)
	}

	return &groupResp, nil
}

// sign performs the actual signing request.
func (c *SignerClient) sign(requests []SignRequest) (string, error) {
	groupResp, err := c.signResponse(requests)
	if err != nil {
		return "", err
	}

	// Concatenate signed transactions and convert to base64
	return hexArrayToBase64(groupResp.Signed)
}

// signList performs a signing request and returns individual base64 strings.
func (c *SignerClient) signList(requests []SignRequest) ([]string, error) {
	groupResp, err := c.signResponse(requests)
	if err != nil {
		return nil, err
	}

	// Convert each signed transaction individually
	result := make([]string, len(groupResp.Signed))
	for i, h := range groupResp.Signed {
		decoded, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i, err)
		}
		result[i] = base64.StdEncoding.EncodeToString(decoded)
	}
	return result, nil
}

func (c *SignerClient) signResponse(requests []SignRequest) (*GroupSignResponse, error) {
	if err := validateRequests(requests); err != nil {
		return nil, err
	}
	groupReq := groupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, ErrSigningRejected
	}
	if resp.StatusCode == 503 {
		return nil, ErrSignerUnavailable
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorBody(resp))
	}

	var groupResp GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return nil, fmt.Errorf("signing failed: %s", groupResp.Error)
	}

	return &groupResp, nil
}

// lsigArgsToMap converts single LsigArgs to LsigArgsMap.
func lsigArgsToMap(authAddress string, args LsigArgs) LsigArgsMap {
	if args == nil {
		return nil
	}
	return LsigArgsMap{authAddress: args}
}
