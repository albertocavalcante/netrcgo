# netrcgo

[![CI](https://github.com/albertocavalcante/netrcgo/actions/workflows/ci.yml/badge.svg)](https://github.com/albertocavalcante/netrcgo/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/albertocavalcante/netrcgo.svg)](https://pkg.go.dev/github.com/albertocavalcante/netrcgo)

A Go library for reading `.netrc` files.

## About .netrc files

The `.netrc` file format is a [widespread and well-used concept](https://everything.curl.dev/usingcurl/netrc.html) for storing login credentials, though not formally standardized. Originally developed for FTP clients, it's now used by many tools including `curl`, `git`, and various HTTP clients.

**Format:**
```
machine hostname
login username
password secret

default
login anonymous
password user@domain.com
```

**File location:** This library looks for `.netrc` in the user's home directory on all platforms (unlike curl which uses `_netrc` on Windows).

## Install

```bash
go get github.com/albertocavalcante/netrcgo
```

## Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/albertocavalcante/netrcgo"
)

func main() {
    // Get credentials from ~/.netrc
    creds, found, err := netrc.GetHostCredentials("api.github.com")
    if err != nil {
        log.Fatal(err)
    }
    if found {
        fmt.Printf("Login: %s\n", creds.Login)
        // Use creds.Password for authentication
    }
}
```

## API

### Core Functions

```go
// Get credentials from default ~/.netrc file
creds, found, err := netrc.GetHostCredentials("hostname")
```

### File Operations

```go
// Use specific .netrc file
f, err := netrc.NewFile("/path/to/.netrc")
creds, found, err := f.GetCredentials("hostname")
```

### Utilities

```go
// Parse .netrc content directly
login, password, found, err := netrc.ParseNetrcFile(content, "hostname")

// Get default .netrc file path
path, err := netrc.DefaultPath()

// Check if credentials are empty
if creds.IsEmpty() {
    // no credentials found
}
```

### Types

```go
type Credentials struct {
    Login    string
    Password string
}
```

## Implementation Notes

- File permission validation on Unix systems (mode 0600 or 0400)
- Cross-platform home directory detection
- Uses `.netrc` filename on all platforms
- Handles `default` machine entries
- Memory-safe parsing with no external dependencies

## Environment Variables

- `NETRC` - Custom path to .netrc file
- `HOME` - User home directory (Unix)
- `USERPROFILE` - User profile directory (Windows)

## Contributing

Contributions welcome! Please check the [issues](https://github.com/albertocavalcante/netrcgo/issues) or open a new one.

## License

MIT License - see [LICENSE](LICENSE) file for details. 