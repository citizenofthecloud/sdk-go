# citizenofthecloud — Go SDK

Identity and authentication for autonomous AI agents. Go SDK.

**Prove who you are. Verify who you're talking to.**

Exposes the full **17-tool Citizen of the Cloud surface** — registration, signing, verification, the challenge/respond loop, registry queries, and a `net/http` route-guard middleware.

---

## Install

```bash
go get github.com/citizenofthecloud/sdk-go
```

Requires Go 1.21+.

```go
import cotc "github.com/citizenofthecloud/sdk-go"
```

---

## The 17-tool surface

| # | Tool | API | Purpose |
|---|---|---|---|
| 1 | lookup-agent | `cotc.LookupAgent(registryURL, cloudID)` | Read another agent's passport |
| 2 | get-server-identity | `identity.GetPassport()` | Fetch your own passport |
| 3 | list-directory | `cotc.ListDirectory(registryURL)` | Browse the public directory |
| 4 | governance-feed | `cotc.GetGovernanceFeed(registryURL)` | Read recent registry events |
| 5 | verify-agent | `cotc.VerifyAgent(headers, policy)` | Verify signed headers (simple) |
| 6 | verify-request | `cotc.VerifyRequest(headers, url, method, body, policy)` | Verify request-bound signature |
| 7 | request-challenge | `cotc.RequestChallenge(registryURL, cloudID)` | Ask the registry for a nonce |
| 8 | respond-to-challenge | `cotc.SubmitChallengeResponse(...)` | Submit a signed nonce |
| 9 | prove-identity | `identity.ProveIdentity()` | Full challenge/sign/respond loop |
| 10 | sign-headers | `identity.Sign()` | Produce timestamp-bound headers |
| 11 | sign-request | `identity.SignRequest(url, method, body)` | Produce request-bound headers |
| 12 | cloud-fetch | `cotc.CloudFetch(identity, url, method, body)` | Auto-signed HTTP request |
| 13 | generate-keypair | `cotc.GenerateKeyPair()` | Make a fresh Ed25519 keypair |
| 14 | trust-policy | `cotc.TrustPolicy{...}` | Reusable verification rules |
| 15 | clear-cache | `cotc.ClearCache()` | Clear the verification cache |
| 16 | http-middleware | `cotc.CloudGuard(policy)` | `net/http` route guard |
| 17 | register-agent | `cotc.RegisterAgent(sdkToken, opts)` | Programmatic agent registration |

---

## Quick start (register → sign → verify)

```go
package main

import (
    "log"
    "net/http"
    "os"
    cotc "github.com/citizenofthecloud/sdk-go"
)

func main() {
    // 1. Register a new agent (one-time; needs an SDK token from /account)
    reg, err := cotc.RegisterAgent(os.Getenv("COTC_SDK_TOKEN"), cotc.RegisterOptions{
        Name:            "My Research Bot",
        DeclaredPurpose: "Summarize papers and surface trends",
        AutonomyLevel:   "tool",
    })
    if err != nil { log.Fatal(err) }
    log.Printf("Cloud ID: %s", reg.CloudID)
    log.Printf("Private key — STORE SECURELY:\n%s", reg.PrivateKey)

    // 2. Sign an outbound request
    me, err := cotc.NewCloudIdentity(cotc.Config{
        CloudID:    reg.CloudID,
        PrivateKey: reg.PrivateKey,
    })
    if err != nil { log.Fatal(err) }

    req, _ := http.NewRequest("POST", "https://other-agent.com/api/task", nil)
    for k, v := range me.Sign().AsMap() {
        req.Header.Set(k, v)
    }
    http.DefaultClient.Do(req)

    // 3. Verify an inbound request
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        result := cotc.VerifyAgent(r.Header, nil)
        if !result.Verified {
            http.Error(w, result.Reason, 401)
            return
        }
        log.Printf("Verified %s (trust %.2f)", result.Agent.Name, result.Agent.TrustScore)
    })
    http.ListenAndServe(":8080", handler)
}
```

---

## Examples per surface

### Key management (#13 generate-keypair)

```go
keys, err := cotc.GenerateKeyPair()
if err != nil { log.Fatal(err) }
// keys.PublicKey  → submit during manual registration
// keys.PrivateKey → keep secret
```

### Registration (#17 register-agent)

```go
reg, err := cotc.RegisterAgent(os.Getenv("COTC_SDK_TOKEN"), cotc.RegisterOptions{
    Name:               "My Research Bot",
    DeclaredPurpose:    "Summarize papers and surface trends",
    AutonomyLevel:      "tool",  // "tool" | "assistant" | "agent" | "self-directing"
    Capabilities:       []string{"summarize", "cite"},
    OperationalDomain:  "research-lab.example.com",
})
```

### Outbound signing (#10, #11, #12)

```go
me, _ := cotc.NewCloudIdentity(cotc.Config{
    CloudID:    os.Getenv("CLOUD_ID"),
    PrivateKey: os.Getenv("CLOUD_PRIVATE_KEY"),
})

// 10 — simple
headers := me.Sign()

// 11 — request-bound (signs URL + method + body hash too)
reqHeaders := me.SignRequest("https://other.example.com/api/data", "POST", `{"q":"x"}`)

// 12 — convenience: HTTP call with auto-signed request-bound headers
resp, err := cotc.CloudFetch(me, "https://other.example.com/api/data", "POST", `{"q":"x"}`)
```

### Inbound verification (#5, #6, #14)

```go
policy := &cotc.TrustPolicy{
    MinimumTrustScore:     0.5,
    RequireCovenant:       true,
    AllowedAutonomyLevels: []string{"agent", "assistant"},
}

// 5 — simple
r1 := cotc.VerifyAgent(req.Header, policy)

// 6 — request-bound
bodyBytes, _ := io.ReadAll(req.Body)
r2 := cotc.VerifyRequest(req.Header, req.URL.String(), req.Method, string(bodyBytes), policy)

if !r2.Verified {
    http.Error(w, r2.Reason, 401)
    return
}
log.Printf("Verified %s", r2.Agent.Name)
```

### Challenge / Respond (#7, #8, #9 prove-identity)

```go
me, _ := cotc.NewCloudIdentity(cotc.Config{CloudID: cloudID, PrivateKey: privateKey})

// 9 — full self-prove loop in one call (recommended)
verified, err := me.ProveIdentity()
log.Println(verified.Verified)   // true

// Or — compose manually:
// 7
ch, _ := cotc.RequestChallenge("https://citizenofthecloud.com", cloudID)
// 8 — pass your base64 signature over the UTF-8 nonce bytes
result, _ := cotc.SubmitChallengeResponse(
    "https://citizenofthecloud.com", cloudID, ch.Nonce, signatureB64,
)
```

### Registry queries (#1, #2, #3, #4)

```go
// 1 — Look up another agent
agent, _ := cotc.LookupAgent("https://citizenofthecloud.com", "cc-abc...")

// 2 — Fetch your own passport
me, _ := cotc.NewCloudIdentity(cotc.Config{CloudID: cloudID, PrivateKey: privateKey})
my, _ := me.GetPassport()

// 3 — Browse the public directory
all, _ := cotc.ListDirectory("https://citizenofthecloud.com")

// 4 — Read the governance event feed
feed, _ := cotc.GetGovernanceFeed("https://citizenofthecloud.com")
```

### `net/http` route guard (#16 http-middleware)

```go
mux := http.NewServeMux()
mux.Handle("/api/task", cotc.CloudGuard(&cotc.TrustPolicy{
    MinimumTrustScore: 0.5,
})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    agent := cotc.GetVerifiedAgent(r)   // attached by the middleware
    fmt.Fprintf(w, "Hello %s", agent.Name)
})))
http.ListenAndServe(":8080", mux)
```

### Cache control (#15 clear-cache)

```go
cotc.ClearCache()   // useful in tests / after a trust-score update
```

---

## Environment variables

| Variable | Description |
|---|---|
| `CLOUD_ID` | Your agent's Cloud ID (e.g., `cc-7f3a9b2e-...`) |
| `CLOUD_PRIVATE_KEY` | Your agent's Ed25519 private key (PEM format) |
| `COTC_SDK_TOKEN` | Bootstrap SDK token (`cotc_sdk_*`) for `RegisterAgent`. Get one at [citizenofthecloud.com/account](https://citizenofthecloud.com/account). |

---

## Links

- [citizenofthecloud.com](https://citizenofthecloud.com)
- [Documentation](https://citizenofthecloud.com/docs)
- [Specification](https://citizenofthecloud.com/spec)
- [Account / SDK tokens](https://citizenofthecloud.com/account)
- Sister SDKs: [sdk-js](https://github.com/citizenofthecloud/sdk-js) · [sdk-python](https://github.com/citizenofthecloud/sdk-python) · [sdk-rust](https://github.com/citizenofthecloud/sdk-rust)
- [MCP server](https://github.com/citizenofthecloud/mcp-server)

## License

MIT
