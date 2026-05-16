// Package cloudidentity provides identity and authentication for autonomous AI agents.
//
// Prove who you are. Verify who you're talking to.
//
// Quick start:
//
//	// Sign outbound requests
//	identity, _ := cloudidentity.NewCloudIdentity(cloudidentity.Config{
//	    CloudID:    os.Getenv("CLOUD_ID"),
//	    PrivateKey: os.Getenv("CLOUD_PRIVATE_KEY"),
//	})
//	headers := identity.Sign()
//
//	// Verify inbound requests
//	result := cloudidentity.VerifyAgent(req.Header, nil)
//	if result.Verified {
//	    fmt.Println("Verified:", result.Agent.Name)
//	}
package cloudidentity

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	Version        = "0.1.0"
	// Canonical host is www. The bare apex 307-redirects here, and Go's
	// net/http strips the Authorization header on cross-host redirects —
	// so callers using the bare apex silently fail RegisterAgent (and any
	// future auth-bearing endpoint) with a 401.
	DefaultRegistry = "https://www.citizenofthecloud.com"
	DefaultMaxAge   = 300 // 5 minutes in seconds
	cacheTTL        = 5 * time.Minute
)

// ─── Errors ──────────────────────────────────────────────────

// CloudSDKError represents an SDK misconfiguration error.
type CloudSDKError struct {
	Message string
}

func (e *CloudSDKError) Error() string {
	return fmt.Sprintf("CloudSDKError: %s", e.Message)
}

// RegistryError represents an error communicating with the registry.
type RegistryError struct {
	Message string
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("RegistryError: %s", e.Message)
}

// ─── Types ───────────────────────────────────────────────────

// Agent represents the data returned from the registry for a verified agent.
type Agent struct {
	CloudID          string      `json:"cloud_id"`
	Name             string      `json:"name"`
	DeclaredPurpose  string      `json:"declared_purpose"`
	AutonomyLevel    string      `json:"autonomy_level"`
	Capabilities     []string    `json:"capabilities"`
	OperationalDomain string     `json:"operational_domain"`
	CovenantSigned   bool        `json:"covenant_signed"`
	Status           string      `json:"status"`
	TrustScore       *float64    `json:"trust_score"`
	RegistrationDate string      `json:"registration_date"`
	LastVerified     *string     `json:"last_verified"`
	PublicKey        string      `json:"public_key"`
	OwnerUsername    *string     `json:"owner_username"`
	Reputation       *Reputation `json:"reputation"`
}

// Reputation holds the Layer 3 component signals exposed alongside the
// composite trust_score. Nil indicates the agent has not yet appeared in a
// refresh of the materialized view (e.g. registered within the last 5 minutes).
// Treat nil as "not enough data yet," not as "zero across all signals."
type Reputation struct {
	Verifications30d      int64    `json:"verifications_30d"`
	LifetimeVerifications int64    `json:"lifetime_verifications"`
	SuccessRate30d        float64  `json:"success_rate_30d"`
	SuccessRateLifetime   float64  `json:"success_rate_lifetime"`
	ReportsFiled          int64    `json:"reports_filed"`
	ReportsUpheld         int64    `json:"reports_upheld"`
	ReportsDismissed      int64    `json:"reports_dismissed"`
	AuthenticatedProofs   int64    `json:"authenticated_proofs"`
	AccountAgeDays        int64    `json:"account_age_days"`
	FirstSeen             *string  `json:"first_seen"`
	LastVerifiedAt        *string  `json:"last_verified_at"`
}

// VerificationResult is returned by VerifyAgent and VerifyRequest.
type VerificationResult struct {
	Verified  bool    `json:"verified"`
	Reason    string  `json:"reason,omitempty"`
	Agent     *Agent  `json:"agent,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
	Latency   float64 `json:"latency"` // milliseconds
}

// KeyPair holds PEM-encoded Ed25519 keys.
type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// SignedHeaders are the authentication headers added to outbound requests.
type SignedHeaders struct {
	CloudID      string
	Timestamp    string
	Signature    string
	RequestBound bool
}

// ToHTTPHeaders converts SignedHeaders to a map for use with HTTP requests.
func (h SignedHeaders) ToHTTPHeaders() map[string]string {
	m := map[string]string{
		"X-Cloud-ID":        h.CloudID,
		"X-Cloud-Timestamp": h.Timestamp,
		"X-Cloud-Signature": h.Signature,
	}
	if h.RequestBound {
		m["X-Cloud-Request-Bound"] = "true"
	}
	return m
}

// SetOnRequest sets the signed headers on an http.Request.
func (h SignedHeaders) SetOnRequest(req *http.Request) {
	req.Header.Set("X-Cloud-ID", h.CloudID)
	req.Header.Set("X-Cloud-Timestamp", h.Timestamp)
	req.Header.Set("X-Cloud-Signature", h.Signature)
	if h.RequestBound {
		req.Header.Set("X-Cloud-Request-Bound", "true")
	}
}

// ─── Key Generation ──────────────────────────────────────────

// GenerateKeyPair generates a new Ed25519 key pair for agent identity.
// Submit the PublicKey during registration.
// Keep the PrivateKey secret — use it to sign requests.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Encode public key to PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("public key encoding failed: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Encode private key to PEM
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("private key encoding failed: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	return &KeyPair{
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

// ─── Cloud Identity ──────────────────────────────────────────

// Config holds the configuration for a CloudIdentity.
type Config struct {
	CloudID     string
	PrivateKey  string
	RegistryURL string
}

// CloudIdentity represents an agent's identity. Used to sign outbound requests.
type CloudIdentity struct {
	CloudID     string
	RegistryURL string
	privateKey  ed25519.PrivateKey
}

// NewCloudIdentity creates a new CloudIdentity from a config.
func NewCloudIdentity(cfg Config) (*CloudIdentity, error) {
	if cfg.CloudID == "" {
		return nil, &CloudSDKError{Message: "CloudID is required"}
	}
	if cfg.PrivateKey == "" {
		return nil, &CloudSDKError{Message: "PrivateKey is required"}
	}

	registryURL := cfg.RegistryURL
	if registryURL == "" {
		registryURL = DefaultRegistry
	}
	registryURL = strings.TrimRight(registryURL, "/")

	// Parse the private key
	block, _ := pem.Decode([]byte(cfg.PrivateKey))
	if block == nil {
		return nil, &CloudSDKError{Message: "invalid private key: failed to decode PEM"}
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &CloudSDKError{Message: fmt.Sprintf("invalid private key: %v", err)}
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, &CloudSDKError{Message: "private key is not Ed25519"}
	}

	return &CloudIdentity{
		CloudID:     cfg.CloudID,
		RegistryURL: registryURL,
		privateKey:  edKey,
	}, nil
}

// Sign generates authentication headers for an outbound request.
// Signature covers: {cloudId}:{timestamp}
func (c *CloudIdentity) Sign() SignedHeaders {
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf("%s:%s", c.CloudID, timestamp)
	signature := ed25519.Sign(c.privateKey, []byte(payload))

	return SignedHeaders{
		CloudID:   c.CloudID,
		Timestamp: timestamp,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
}

// SignRequest generates request-bound authentication headers.
// Signature covers: {cloudId}:{timestamp}:{method}:{url}:{bodyHash}
func (c *CloudIdentity) SignRequest(reqURL, method, body string) SignedHeaders {
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	bodyHash := sha256.Sum256([]byte(body))
	bodyHashB64 := base64.RawURLEncoding.EncodeToString(bodyHash[:])
	payload := fmt.Sprintf("%s:%s:%s:%s:%s",
		c.CloudID, timestamp, strings.ToUpper(method), reqURL, bodyHashB64)
	signature := ed25519.Sign(c.privateKey, []byte(payload))

	return SignedHeaders{
		CloudID:      c.CloudID,
		Timestamp:    timestamp,
		Signature:    base64.RawURLEncoding.EncodeToString(signature),
		RequestBound: true,
	}
}

// GetPassport fetches this agent's passport from the registry.
func (c *CloudIdentity) GetPassport() (*Agent, error) {
	u := fmt.Sprintf("%s/api/verify?cloud_id=%s", c.RegistryURL, url.QueryEscape(c.CloudID))
	data, err := fetchJSON(u)
	if err != nil {
		return nil, err
	}

	agentData, ok := data["agent"].(map[string]interface{})
	if !ok {
		return nil, &RegistryError{Message: "invalid agent data in response"}
	}

	agent := parseAgent(agentData)
	return agent, nil
}

// ProveIdentity completes the full challenge/respond cryptographic loop against
// the registry: requests a nonce, signs it with the private key, submits the
// response, and returns the verification result. The resulting verification_log
// row on the registry is server-witnessed (authenticated=true) and contributes
// to this agent's trust score.
func (c *CloudIdentity) ProveIdentity() (*VerificationResult, error) {
	challenge, err := RequestChallenge(c.RegistryURL, c.CloudID)
	if err != nil {
		return nil, err
	}
	// Server signs over the UTF-8 bytes of the hex nonce string (not the
	// decoded hex bytes) — see registry's lib/verification.js.
	sig := ed25519.Sign(c.privateKey, []byte(challenge.Nonce))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	return SubmitChallengeResponse(c.RegistryURL, c.CloudID, challenge.Nonce, sigB64)
}

// ─── Challenge / Respond ─────────────────────────────────────

// ChallengeResult holds a nonce returned from /api/verify/challenge.
type ChallengeResult struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expires_in"`
}

// RequestChallenge requests a verification challenge for cloudID from the
// registry. The returned nonce must be signed with the agent's private key
// (over the UTF-8 bytes of the hex string) and submitted via
// SubmitChallengeResponse.
func RequestChallenge(registryURL, cloudID string) (*ChallengeResult, error) {
	registryURL = strings.TrimRight(registryURL, "/")
	payload, _ := json.Marshal(map[string]string{"cloud_id": cloudID})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		registryURL+"/api/verify/challenge",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, &RegistryError{Message: fmt.Sprintf("cannot reach registry: %v", err)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var errData map[string]interface{}
		if json.Unmarshal(body, &errData) == nil {
			if msg, ok := errData["error"].(string); ok {
				return nil, &RegistryError{Message: msg}
			}
		}
		return nil, &RegistryError{Message: fmt.Sprintf("challenge request failed: %d", resp.StatusCode)}
	}

	var result ChallengeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RegistryError{Message: "invalid JSON response"}
	}
	return &result, nil
}

// SubmitChallengeResponse submits a signed challenge response to the registry.
// The registry validates the signature against the agent's registered public
// key and returns the verified agent. signature must be standard base64-encoded
// (not URL-safe).
func SubmitChallengeResponse(registryURL, cloudID, nonce, signature string) (*VerificationResult, error) {
	registryURL = strings.TrimRight(registryURL, "/")
	payload, _ := json.Marshal(map[string]string{
		"cloud_id":  cloudID,
		"nonce":     nonce,
		"signature": signature,
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		registryURL+"/api/verify/respond",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, &RegistryError{Message: fmt.Sprintf("cannot reach registry: %v", err)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// respond returns non-2xx for failed verification but still includes a
	// parseable body — return it as a VerificationResult so callers can read
	// .Verified and the error field.
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, &RegistryError{Message: fmt.Sprintf("invalid JSON response (status %d)", resp.StatusCode)}
	}

	result := &VerificationResult{}
	if v, ok := raw["verified"].(bool); ok {
		result.Verified = v
	}
	if ts, ok := raw["timestamp"].(string); ok {
		result.Timestamp = ts
	}
	if errStr, ok := raw["error"].(string); ok {
		result.Reason = errStr
	}
	if agentData, ok := raw["agent"].(map[string]interface{}); ok {
		result.Agent = parseAgent(agentData)
	}
	return result, nil
}

// ─── Registry queries (no auth) ──────────────────────────────

// LookupAgent fetches an agent's public record by cloud_id.
// Returns nil if the agent is not found.
func LookupAgent(registryURL, cloudID string) (*Agent, error) {
	u := fmt.Sprintf("%s/api/verify?cloud_id=%s",
		strings.TrimRight(registryURL, "/"),
		url.QueryEscape(cloudID),
	)
	data, err := fetchJSON(u)
	if err != nil {
		return nil, err
	}
	if verified, _ := data["verified"].(bool); !verified {
		return nil, nil
	}
	agentData, ok := data["agent"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	return parseAgent(agentData), nil
}

// ListDirectory returns the public agent directory.
func ListDirectory(registryURL string) ([]*Agent, error) {
	u := fmt.Sprintf("%s/api/directory", strings.TrimRight(registryURL, "/"))
	data, err := fetchJSON(u)
	if err != nil {
		return nil, err
	}

	rawList, _ := data["agents"].([]interface{})
	agents := make([]*Agent, 0, len(rawList))
	for _, item := range rawList {
		if m, ok := item.(map[string]interface{}); ok {
			agents = append(agents, parseAgent(m))
		}
	}
	return agents, nil
}

// GetGovernanceFeed returns the governance activity feed.
func GetGovernanceFeed(registryURL string) ([]map[string]interface{}, error) {
	u := fmt.Sprintf("%s/api/governance/feed", strings.TrimRight(registryURL, "/"))
	data, err := fetchJSON(u)
	if err != nil {
		return nil, err
	}

	rawList, _ := data["feed"].([]interface{})
	feed := make([]map[string]interface{}, 0, len(rawList))
	for _, item := range rawList {
		if m, ok := item.(map[string]interface{}); ok {
			feed = append(feed, m)
		}
	}
	return feed, nil
}

// ─── Registration (SDK token auth) ───────────────────────────

// RegisterOptions configures a call to RegisterAgent.
type RegisterOptions struct {
	Name              string
	DeclaredPurpose   string
	AutonomyLevel     string   // 'tool' | 'assistant' | 'agent' | 'self-directing'; default 'tool'
	Capabilities      []string
	OperationalDomain string
	CovenantSigned    bool     // must be true
	RegistryURL       string   // default DefaultRegistry
}

// RegisterResult is returned by RegisterAgent. PrivateKey is yours to keep —
// it is never sent to the registry.
type RegisterResult struct {
	CloudID         string                 `json:"cloud_id"`
	PublicKey       string                 `json:"public_key"`
	PrivateKey      string                 `json:"private_key"`
	Name            string                 `json:"name"`
	DeclaredPurpose string                 `json:"declared_purpose"`
	AutonomyLevel   string                 `json:"autonomy_level"`
	Passport        map[string]interface{} `json:"passport,omitempty"`
}

// RegisterAgent generates a fresh Ed25519 keypair locally, posts the public
// key plus the agent metadata to the registry under the supplied SDK token,
// and returns the cloud_id with both keys. The private key never leaves the
// caller's process.
//
// The sdkToken must be a "cotc_sdk_*" token issued from the user's account
// at citizenofthecloud.com/account.
func RegisterAgent(sdkToken string, opts RegisterOptions) (*RegisterResult, error) {
	if !strings.HasPrefix(sdkToken, "cotc_sdk_") {
		return nil, &CloudSDKError{Message: "sdkToken must be a cotc_sdk_* token. Create one at citizenofthecloud.com/account."}
	}
	if opts.AutonomyLevel == "" {
		opts.AutonomyLevel = "tool"
	}
	registry := opts.RegistryURL
	if registry == "" {
		registry = DefaultRegistry
	}
	covenant := opts.CovenantSigned

	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"name":             opts.Name,
		"declared_purpose": opts.DeclaredPurpose,
		"autonomy_level":   opts.AutonomyLevel,
		"public_key":       kp.PublicKey,
		"covenant_signed":  covenant,
		"capabilities":     opts.Capabilities,
	}
	if opts.OperationalDomain != "" {
		payload["operational_domain"] = opts.OperationalDomain
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/register", strings.TrimRight(registry, "/")),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, &RegistryError{Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sdkToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &RegistryError{Message: err.Error()}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody map[string]interface{}
		_ = json.Unmarshal(respBody, &errBody)
		msg, _ := errBody["error"].(string)
		if msg == "" {
			msg, _ = errBody["error_code"].(string)
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, &RegistryError{Message: "Registration failed: " + msg}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, &RegistryError{Message: "invalid response: " + err.Error()}
	}
	cloudID, _ := data["cloud_id"].(string)
	passport, _ := data["passport"].(map[string]interface{})

	return &RegisterResult{
		CloudID:         cloudID,
		PublicKey:       kp.PublicKey,
		PrivateKey:      kp.PrivateKey,
		Name:            opts.Name,
		DeclaredPurpose: opts.DeclaredPurpose,
		AutonomyLevel:   opts.AutonomyLevel,
		Passport:        passport,
	}, nil
}

// ─── Trust Policy ────────────────────────────────────────────

// TrustPolicy defines reusable trust rules for verification.
type TrustPolicy struct {
	MaxAge                int      // Maximum signature age in seconds (default: 300)
	RequireCovenant       bool     // Reject if covenant not signed (default: true)
	MinimumTrustScore     *float64 // Reject below this trust score
	AllowedAutonomyLevels []string // Restrict to these levels
	BlockedAgents         []string // Reject these Cloud IDs
	RegistryURL           string   // Custom registry URL
	Cache                 bool     // Cache public keys (default: true)
}

// DefaultPolicy returns a TrustPolicy with default settings.
func DefaultPolicy() *TrustPolicy {
	return &TrustPolicy{
		MaxAge:          DefaultMaxAge,
		RequireCovenant: true,
		RegistryURL:     DefaultRegistry,
		Cache:           true,
	}
}

// ─── Cache ───────────────────────────────────────────────────

type cacheEntry struct {
	agent *Agent
	time  time.Time
}

var (
	agentCache = make(map[string]*cacheEntry)
	cacheMu    sync.RWMutex
)

func getCached(cloudID string) *Agent {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	entry, ok := agentCache[cloudID]
	if !ok {
		return nil
	}
	if time.Since(entry.time) > cacheTTL {
		delete(agentCache, cloudID)
		return nil
	}
	return entry.agent
}

func setCache(cloudID string, agent *Agent) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	agentCache[cloudID] = &cacheEntry{agent: agent, time: time.Now()}
}

// ClearCache clears the verification cache.
func ClearCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	agentCache = make(map[string]*cacheEntry)
}

// ─── Verification ────────────────────────────────────────────

// VerifyAgent verifies incoming request headers from another agent.
// Pass nil for policy to use defaults.
func VerifyAgent(headers http.Header, policy *TrustPolicy) *VerificationResult {
	result := verifyAgentInner(headers, policy)

	// Log the verification result (best-effort, non-blocking)
	p := resolvePolicy(policy)
	cloudID := getHeader(headers, "X-Cloud-ID")
	if cloudID == "" {
		cloudID = "unknown"
	}
	logResult := "success"
	if !result.Verified {
		logResult = result.Reason
	}
	go logVerification(p.RegistryURL, cloudID, logResult, result.Reason, result.Latency)

	return result
}

// VerifyAgentFromMap verifies headers from a map[string]string (convenience).
func VerifyAgentFromMap(headers map[string]string, policy *TrustPolicy) *VerificationResult {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return VerifyAgent(h, policy)
}

func resolvePolicy(policy *TrustPolicy) *TrustPolicy {
	if policy == nil {
		return DefaultPolicy()
	}
	if policy.MaxAge == 0 {
		policy.MaxAge = DefaultMaxAge
	}
	if policy.RegistryURL == "" {
		policy.RegistryURL = DefaultRegistry
	}
	return policy
}

func verifyAgentInner(headers http.Header, policy *TrustPolicy) *VerificationResult {
	start := time.Now()
	p := resolvePolicy(policy)

	cloudID := getHeader(headers, "X-Cloud-ID")
	timestamp := getHeader(headers, "X-Cloud-Timestamp")
	signature := getHeader(headers, "X-Cloud-Signature")

	// 1. Check headers present
	if cloudID == "" || timestamp == "" || signature == "" {
		return &VerificationResult{
			Verified: false,
			Reason:   "missing_headers",
			Latency:  ms(start),
		}
	}

	// 2. Check blocked list
	if len(p.BlockedAgents) > 0 {
		for _, blocked := range p.BlockedAgents {
			if blocked == cloudID {
				return &VerificationResult{
					Verified: false,
					Reason:   "agent_blocked",
					Latency:  ms(start),
				}
			}
		}
	}

	// 3. Validate timestamp
	signedAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		// Try ISO format with timezone offset
		signedAt, err = time.Parse("2006-01-02T15:04:05.999999-07:00", timestamp)
		if err != nil {
			signedAt, err = time.Parse(time.RFC3339, timestamp)
			if err != nil {
				return &VerificationResult{
					Verified: false,
					Reason:   "invalid_timestamp",
					Latency:  ms(start),
				}
			}
		}
	}

	age := time.Since(signedAt).Seconds()
	if age > float64(p.MaxAge) {
		return &VerificationResult{
			Verified: false,
			Reason:   "timestamp_expired",
			Latency:  ms(start),
		}
	}
	if age < -30 {
		return &VerificationResult{
			Verified: false,
			Reason:   "timestamp_future",
			Latency:  ms(start),
		}
	}

	// 4. Lookup agent in registry (with cache)
	var agentData *Agent
	if p.Cache {
		agentData = getCached(cloudID)
	}

	if agentData == nil {
		registryURL := strings.TrimRight(p.RegistryURL, "/")
		u := fmt.Sprintf("%s/api/verify?cloud_id=%s", registryURL, url.QueryEscape(cloudID))
		data, err := fetchJSON(u)
		if err != nil {
			return &VerificationResult{
				Verified: false,
				Reason:   "registry_unreachable",
				Latency:  ms(start),
			}
		}

		verified, _ := data["verified"].(bool)
		agentRaw, hasAgent := data["agent"].(map[string]interface{})
		if !verified || !hasAgent {
			return &VerificationResult{
				Verified: false,
				Reason:   "invalid_cloud_id",
				Latency:  ms(start),
			}
		}

		agentData = parseAgent(agentRaw)
		if p.Cache {
			setCache(cloudID, agentData)
		}
	}

	// 5. Check agent status
	if agentData.Status != "active" {
		return &VerificationResult{
			Verified: false,
			Reason:   "agent_suspended",
			Agent:    agentData,
			Latency:  ms(start),
		}
	}

	// 6. Check covenant
	if p.RequireCovenant && !agentData.CovenantSigned {
		return &VerificationResult{
			Verified: false,
			Reason:   "covenant_unsigned",
			Agent:    agentData,
			Latency:  ms(start),
		}
	}

	// 7. Check trust score
	if p.MinimumTrustScore != nil {
		if agentData.TrustScore == nil || *agentData.TrustScore < *p.MinimumTrustScore {
			return &VerificationResult{
				Verified: false,
				Reason:   "trust_score_insufficient",
				Agent:    agentData,
				Latency:  ms(start),
			}
		}
	}

	// 8. Check autonomy level
	if len(p.AllowedAutonomyLevels) > 0 {
		allowed := false
		for _, level := range p.AllowedAutonomyLevels {
			if level == agentData.AutonomyLevel {
				allowed = true
				break
			}
		}
		if !allowed {
			return &VerificationResult{
				Verified: false,
				Reason:   "autonomy_level_restricted",
				Agent:    agentData,
				Latency:  ms(start),
			}
		}
	}

	// 9. Verify cryptographic signature
	pubBlock, _ := pem.Decode([]byte(agentData.PublicKey))
	if pubBlock == nil {
		return &VerificationResult{
			Verified: false,
			Reason:   "invalid_signature",
			Agent:    agentData,
			Latency:  ms(start),
		}
	}

	pubKeyRaw, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return &VerificationResult{
			Verified: false,
			Reason:   "invalid_signature",
			Agent:    agentData,
			Latency:  ms(start),
		}
	}

	pubKey, ok := pubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return &VerificationResult{
			Verified: false,
			Reason:   "invalid_signature",
			Agent:    agentData,
			Latency:  ms(start),
		}
	}

	payload := fmt.Sprintf("%s:%s", cloudID, timestamp)
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		// Try standard base64url with padding
		sigBytes, err = base64.URLEncoding.DecodeString(signature)
		if err != nil {
			return &VerificationResult{
				Verified: false,
				Reason:   "invalid_signature",
				Agent:    agentData,
				Latency:  ms(start),
			}
		}
	}

	if !ed25519.Verify(pubKey, []byte(payload), sigBytes) {
		cacheMu.Lock()
		delete(agentCache, cloudID)
		cacheMu.Unlock()
		return &VerificationResult{
			Verified: false,
			Reason:   "invalid_signature",
			Agent:    agentData,
			Latency:  ms(start),
		}
	}

	// 10. All checks passed
	return &VerificationResult{
		Verified:  true,
		Agent:     agentData,
		Timestamp: timestamp,
		Latency:   ms(start),
	}
}

// VerifyRequest verifies with request-bound signature validation.
func VerifyRequest(headers http.Header, reqURL, method, body string, policy *TrustPolicy) *VerificationResult {
	requestBound := getHeader(headers, "X-Cloud-Request-Bound")
	if requestBound == "" {
		return VerifyAgent(headers, policy)
	}

	start := time.Now()
	p := resolvePolicy(policy)

	// Run basic checks via inner (skip logging, we'll log at the end)
	basic := verifyAgentInner(headers, policy)
	if !basic.Verified && basic.Reason != "invalid_signature" {
		return basic
	}

	if basic.Agent == nil {
		return &VerificationResult{
			Verified: false,
			Reason:   "invalid_cloud_id",
			Latency:  ms(start),
		}
	}

	cloudID := getHeader(headers, "X-Cloud-ID")
	timestamp := getHeader(headers, "X-Cloud-Timestamp")
	signature := getHeader(headers, "X-Cloud-Signature")

	// Verify request-bound signature
	pubBlock, _ := pem.Decode([]byte(basic.Agent.PublicKey))
	if pubBlock == nil {
		return &VerificationResult{Verified: false, Reason: "invalid_signature", Agent: basic.Agent, Latency: ms(start)}
	}

	pubKeyRaw, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return &VerificationResult{Verified: false, Reason: "invalid_signature", Agent: basic.Agent, Latency: ms(start)}
	}

	pubKey, ok := pubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return &VerificationResult{Verified: false, Reason: "invalid_signature", Agent: basic.Agent, Latency: ms(start)}
	}

	bodyHash := sha256.Sum256([]byte(body))
	bodyHashB64 := base64.RawURLEncoding.EncodeToString(bodyHash[:])
	payload := fmt.Sprintf("%s:%s:%s:%s:%s",
		cloudID, timestamp, strings.ToUpper(method), reqURL, bodyHashB64)

	sigBytes, _ := base64.RawURLEncoding.DecodeString(signature)

	if !ed25519.Verify(pubKey, []byte(payload), sigBytes) {
		return &VerificationResult{
			Verified: false,
			Reason:   "invalid_signature",
			Agent:    basic.Agent,
			Latency:  ms(start),
		}
	}

	result := &VerificationResult{
		Verified:  true,
		Agent:     basic.Agent,
		Timestamp: timestamp,
		Latency:   ms(start),
	}

	go logVerification(p.RegistryURL, cloudID, "success", "", result.Latency)

	return result
}

// ─── HTTP Middleware ──────────────────────────────────────────

// CloudGuard returns an http.Handler middleware that verifies Cloud Identity headers.
// On success, the verified agent is stored in the request context.
// On failure, returns 401.
func CloudGuard(policy *TrustPolicy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := VerifyAgent(r.Header, policy)
			if result.Verified {
				// Store agent in request header for downstream handlers
				agentJSON, _ := json.Marshal(result.Agent)
				r.Header.Set("X-Cloud-Verified-Agent", string(agentJSON))
				next.ServeHTTP(w, r)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":  "Cloud Identity verification failed",
					"reason": result.Reason,
				})
			}
		})
	}
}

// GetVerifiedAgent extracts the verified agent from the request (set by CloudGuard middleware).
func GetVerifiedAgent(r *http.Request) *Agent {
	agentJSON := r.Header.Get("X-Cloud-Verified-Agent")
	if agentJSON == "" {
		return nil
	}
	var agent Agent
	if err := json.Unmarshal([]byte(agentJSON), &agent); err != nil {
		return nil
	}
	return &agent
}

// ─── Logging ─────────────────────────────────────────────────

func logVerification(registryURL, cloudID, result, reason string, latency float64) {
	defer func() { recover() }() // Never panic from logging

	logURL := fmt.Sprintf("%s/api/verify/log", strings.TrimRight(registryURL, "/"))

	body, _ := json.Marshal(map[string]interface{}{
		"cloud_id": cloudID,
		"result":   result,
		"reason":   reason,
		"method":   "sdk_headers",
		"latency":  latency,
	})

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(logURL, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

// ─── Internal helpers ────────────────────────────────────────

func getHeader(h http.Header, name string) string {
	v := h.Get(name)
	if v == "" {
		v = h.Get(strings.ToLower(name))
	}
	return v
}

func ms(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func fetchJSON(u string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, &RegistryError{Message: fmt.Sprintf("cannot reach registry: %v", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RegistryError{Message: "failed to read response"}
	}

	if resp.StatusCode == 404 {
		return map[string]interface{}{"verified": false}, nil
	}
	if resp.StatusCode != 200 {
		return nil, &RegistryError{Message: fmt.Sprintf("registry returned %d", resp.StatusCode)}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, &RegistryError{Message: "invalid JSON response"}
	}

	return data, nil
}

func parseAgent(data map[string]interface{}) *Agent {
	agent := &Agent{}

	if v, ok := data["cloud_id"].(string); ok {
		agent.CloudID = v
	}
	if v, ok := data["name"].(string); ok {
		agent.Name = v
	}
	if v, ok := data["declared_purpose"].(string); ok {
		agent.DeclaredPurpose = v
	}
	if v, ok := data["autonomy_level"].(string); ok {
		agent.AutonomyLevel = v
	}
	if v, ok := data["operational_domain"].(string); ok {
		agent.OperationalDomain = v
	}
	if v, ok := data["covenant_signed"].(bool); ok {
		agent.CovenantSigned = v
	}
	if v, ok := data["status"].(string); ok {
		agent.Status = v
	}
	if v, ok := data["trust_score"].(float64); ok {
		agent.TrustScore = &v
	}
	if v, ok := data["registration_date"].(string); ok {
		agent.RegistrationDate = v
	}
	if v, ok := data["last_verified"].(string); ok {
		agent.LastVerified = &v
	}
	if v, ok := data["public_key"].(string); ok {
		agent.PublicKey = v
	}
	if v, ok := data["owner_username"].(string); ok {
		agent.OwnerUsername = &v
	}
	if v, ok := data["capabilities"].([]interface{}); ok {
		for _, c := range v {
			if s, ok := c.(string); ok {
				agent.Capabilities = append(agent.Capabilities, s)
			}
		}
	}
	if v, ok := data["reputation"].(map[string]interface{}); ok {
		agent.Reputation = parseReputation(v)
	}

	return agent
}

func parseReputation(data map[string]interface{}) *Reputation {
	r := &Reputation{}
	asInt := func(v interface{}) int64 {
		if f, ok := v.(float64); ok {
			return int64(f)
		}
		return 0
	}
	asFloat := func(v interface{}) float64 {
		if f, ok := v.(float64); ok {
			return f
		}
		return 0
	}
	r.Verifications30d = asInt(data["verifications_30d"])
	r.LifetimeVerifications = asInt(data["lifetime_verifications"])
	r.SuccessRate30d = asFloat(data["success_rate_30d"])
	r.SuccessRateLifetime = asFloat(data["success_rate_lifetime"])
	r.ReportsFiled = asInt(data["reports_filed"])
	r.ReportsUpheld = asInt(data["reports_upheld"])
	r.ReportsDismissed = asInt(data["reports_dismissed"])
	r.AuthenticatedProofs = asInt(data["authenticated_proofs"])
	r.AccountAgeDays = asInt(data["account_age_days"])
	if v, ok := data["first_seen"].(string); ok {
		r.FirstSeen = &v
	}
	if v, ok := data["last_verified_at"].(string); ok {
		r.LastVerifiedAt = &v
	}
	return r
}

// ─── Convenience: CloudFetch ─────────────────────────────────

// CloudFetch makes an HTTP request with automatic Cloud Identity signing.
func CloudFetch(identity *CloudIdentity, reqURL, method string, body string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(strings.ToUpper(method), reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	headers := identity.SignRequest(reqURL, method, body)
	headers.SetOnRequest(req)

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// ─── Signature helper (exported for use by other packages) ───

// VerifySignature verifies an Ed25519 signature against a PEM public key.
func VerifySignature(publicKeyPEM, payload string, signatureB64 string) bool {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false
	}

	pubKeyRaw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	pubKey, ok := pubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return false
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}

	return ed25519.Verify(pubKey, []byte(payload), sigBytes)
}

// SignPayload signs a payload with a PEM-encoded Ed25519 private key.
func SignPayload(privateKeyPEM, payload string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", &CloudSDKError{Message: "invalid private key PEM"}
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", &CloudSDKError{Message: fmt.Sprintf("invalid private key: %v", err)}
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", &CloudSDKError{Message: "not an Ed25519 key"}
	}

	sig, err := edKey.Sign(rand.Reader, []byte(payload), crypto.Hash(0))
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(sig), nil
}
