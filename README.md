# cloudidentity

Identity and authentication for autonomous AI agents. Go SDK.

**Prove who you are. Verify who you're talking to.**

## Install

The Go SDK is distributed via Go's module proxy. Until a versioned tag lands, pin to the latest commit on `main`:

```bash
go get github.com/citizenofthecloud/sdk-go@main
```

Tagged releases will follow once the API stabilizes; for now `@main` gives you the latest features (most recently: `RegisterAgent()` and SDK-token auth).

## Quick Start

### Register a new agent (one-time setup)

Bootstrap a new Cloud Identity agent in a single call. Generates a fresh Ed25519 keypair locally, posts the public key to the registry under your SDK token, and returns the `cloud_id` together with both keys. The private key never leaves your process — store it securely.

Get an SDK token from [citizenofthecloud.com/account](https://citizenofthecloud.com/account).

```go
package main

import (
    "fmt"
    "os"
    cloud "github.com/citizenofthecloud/sdk-go"
)

func main() {
    result, err := cloud.RegisterAgent(
        os.Getenv("COTC_SDK_TOKEN"),
        cloud.RegisterOptions{
            Name:            "My Research Bot",
            DeclaredPurpose: "Summarize papers and surface trends",
            AutonomyLevel:   "tool",
            CovenantSigned:  true,
        },
    )
    if err != nil {
        panic(err)
    }

    fmt.Println(result.CloudID)
    fmt.Println(result.PublicKey)
    fmt.Println(result.PrivateKey)  // STORE SECURELY — the server keeps only the public key
}
```

The returned `CloudID` and `PrivateKey` are the inputs to `NewCloudIdentity` for signing subsequent requests.

### Sign outbound requests

```go
package main

import (
    "fmt"
    "net/http"
    "os"
    cloud "github.com/citizenofthecloud/sdk-go"
)

func main() {
    identity, err := cloud.NewCloudIdentity(cloud.Config{
        CloudID:    os.Getenv("CLOUD_ID"),
        PrivateKey: os.Getenv("CLOUD_PRIVATE_KEY"),
    })
    if err != nil {
        panic(err)
    }

    // Sign and make a request
    req, _ := http.NewRequest("POST", "https://other-agent.com/api/task", nil)
    headers := identity.Sign()
    headers.SetOnRequest(req)

    resp, _ := http.DefaultClient.Do(req)
    fmt.Println(resp.Status)
}
```

### Verify inbound requests

```go
func handler(w http.ResponseWriter, r *http.Request) {
    result := cloud.VerifyAgent(r.Header, nil)

    if result.Verified {
        fmt.Printf("Verified: %s\n", result.Agent.Name)
        fmt.Printf("Trust: %v\n", result.Agent.TrustScore)
    } else {
        fmt.Printf("Rejected: %s\n", result.Reason)
        http.Error(w, "Unauthorized", 401)
    }
}
```

### HTTP middleware (one-line protection)

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/task", taskHandler)

// Wrap with Cloud Identity verification
protected := cloud.CloudGuard(nil)(mux)
http.ListenAndServe(":8080", protected)

func taskHandler(w http.ResponseWriter, r *http.Request) {
    agent := cloud.GetVerifiedAgent(r)
    fmt.Printf("Request from %s\n", agent.Name)
}
```

### With Trust Policy

```go
minScore := 0.7
policy := &cloud.TrustPolicy{
    MinimumTrustScore:     &minScore,
    AllowedAutonomyLevels: []string{"agent", "assistant"},
    BlockedAgents:         []string{"cc-known-bad-actor"},
}

result := cloud.VerifyAgent(r.Header, policy)
```

### Generate keys without registering

```go
keys, err := cloud.GenerateKeyPair()
if err != nil {
    panic(err)
}
fmt.Println(keys.PublicKey)  // Submit during manual registration
fmt.Println(keys.PrivateKey) // Keep secret
```

## Environment Variables

| Variable | Description |
|---|---|
| `CLOUD_ID` | Your agent's Cloud ID (e.g., `cc-7f3a9b2e-...`) |
| `CLOUD_PRIVATE_KEY` | Your agent's Ed25519 private key (PEM format) |
| `COTC_SDK_TOKEN` | Bootstrap SDK token (`cotc_sdk_*`) for `RegisterAgent()`. Obtain from [citizenofthecloud.com/account](https://citizenofthecloud.com/account). |

## Links

- [Citizen of the Cloud](https://citizenofthecloud.com)
- [SDK Documentation](https://citizenofthecloud.com/docs)
- [Account / SDK tokens](https://citizenofthecloud.com/account)

## License

MIT
