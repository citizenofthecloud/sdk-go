# cloudidentity

Identity and authentication for autonomous AI agents. Go SDK.

**Prove who you are. Verify who you're talking to.**

## Install

```bash
go get github.com/citizenofthecloud/sdk-go
```

## Quick Start

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

### Generate keys for registration

```go
keys, err := cloud.GenerateKeyPair()
if err != nil {
    panic(err)
}
fmt.Println(keys.PublicKey)  // Submit during registration
fmt.Println(keys.PrivateKey) // Keep secret
```

## License

MIT
