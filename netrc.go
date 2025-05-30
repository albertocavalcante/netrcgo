// Package netrc provides functionality for reading and parsing .netrc files.
//
// Security Note: .netrc files store credentials in plaintext and should have
// restrictive permissions (0600) to prevent unauthorized access. This package
// validates file permissions and will return an error if the file is readable
// by others.
//
// Example usage:
//
//	// Get credentials for a specific host
//	creds, found, err := netrc.GetHostCredentials("example.com")
//	if err != nil {
//		log.Fatal(err)
//	}
//	if found {
//		fmt.Printf("User: %s\n", creds.Login)
//	}
//
//	// Use a specific .netrc file
//	f, err := netrc.NewFile("/path/to/.netrc")
//	if err != nil {
//		log.Fatal(err)
//	}
//	creds, found, err := f.GetCredentials("example.com")
package netrc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

// DefaultNetrcFilename is the standard filename for netrc files.
const DefaultNetrcFilename = ".netrc"

// Credentials represents a username and password pair from a .netrc file.
// It holds the Login (username) and Password.
type Credentials struct {
	Login    string
	Password string
}

// IsEmpty returns true if both Login and Password are empty.
func (c Credentials) IsEmpty() bool {
	return c.Login == "" && c.Password == ""
}

// File represents a .netrc file and provides methods to retrieve credentials.
// Its main purpose is to encapsulate the file path.
type File struct {
	path string
}

// NewFile creates a new File instance for the specified .netrc file path.
// If the provided path is empty, it uses the default .netrc file location.
func NewFile(path string) (*File, error) {
	if path == "" {
		var err error

		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}

	return &File{path: path}, nil
}

// DefaultPath returns the path to the default .netrc file.
// It checks NETRC, USERPROFILE, HOME environment variables, then os.UserHomeDir().
func DefaultPath() (string, error) {
	if netrcPath := os.Getenv("NETRC"); netrcPath != "" {
		return netrcPath, nil
	}

	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		return filepath.Join(userProfile, DefaultNetrcFilename), nil
	}

	if homeEnv := os.Getenv("HOME"); homeEnv != "" {
		return filepath.Join(homeEnv, DefaultNetrcFilename), nil
	}

	osHome, err := os.UserHomeDir()
	if err == nil && osHome != "" {
		return filepath.Join(osHome, DefaultNetrcFilename), nil
	}

	return "", errors.New("netrc: could not determine home directory " +
		"(checked NETRC, USERPROFILE, HOME, and os.UserHomeDir)")
}

// validateFilePermissions checks if the .netrc file has secure permissions.
// On Unix-like systems, it ensures the file is not readable by group or others.
func validateFilePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Errorf("netrc: .netrc file %q has insecure permissions %o, should be 0600 or more restrictive", path, perm)
	}

	return nil
}

// GetCredentials reads the .netrc file and parses it to find credentials for the specified host.
// If the .netrc file does not exist, it returns false for found and no error.
func (f *File) GetCredentials(host string) (Credentials, bool, error) {
	if host == "" {
		return Credentials{}, false, fmt.Errorf("netrc: host cannot be empty")
	}

	if _, err := os.Stat(f.path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Credentials{}, false, nil
		}

		return Credentials{}, false, fmt.Errorf("netrc: failed to stat file %q: %w", f.path, err)
	}

	if err := validateFilePermissions(f.path); err != nil {
		return Credentials{}, false, err
	}

	data, err := os.ReadFile(f.path) // Changed from ioutil.ReadFile
	if err != nil {
		return Credentials{}, false, fmt.Errorf("netrc: failed to read file %q: %w", f.path, err)
	}

	login, password, found, parseErr := ParseNetrcFile(string(data), host)
	if parseErr != nil {
		return Credentials{}, false, fmt.Errorf("netrc: failed to parse file %q: %w", f.path, parseErr)
	}

	if !found {
		return Credentials{}, false, nil
	}

	return Credentials{
		Login:    login,
		Password: password,
	}, true, nil
}

// GetHostCredentials is a convenience function that gets credentials for the specified host
// using the default .netrc path.
func GetHostCredentials(host string) (Credentials, bool, error) {
	path, err := DefaultPath()
	if err != nil {
		return Credentials{}, false, err
	}

	f, err := NewFile(path)
	if err != nil {
		return Credentials{}, false, err
	}

	return f.GetCredentials(host)
}

// handleEscapeSequence processes an escape sequence starting at s[currentIndex+1]
// and appends the unescaped character(s) to sb.
// It returns the new index in s after processing the escape sequence.
func handleEscapeSequence(sb *strings.Builder, s string, currentIndex int) int {
	newIndex := currentIndex + 1
	if newIndex >= len(s) { // Backslash at the very end of the string
		sb.WriteRune('\\')

		return currentIndex // Stay at the current index, loop will increment past it
	}

	escapedChar := s[newIndex]
	switch escapedChar {
	case 'n':
		sb.WriteRune('\n')
	case 'r':
		sb.WriteRune('\r')
	case 't':
		sb.WriteRune('\t')
	case '"':
		sb.WriteRune('"')
	case '\\':
		sb.WriteRune('\\')
	default: // Unknown escape sequence, preserve backslash and character
		sb.WriteRune('\\')
		sb.WriteRune(rune(escapedChar))
	}

	return newIndex // newIndex is where the escaped character was
}

// unquoteToken removes surrounding double quotes from a token and unescapes sequences.
// Supported escapes: \n, \r, \t, \", \\.
// Unknown escapes (e.g., \q) result in the backslash and the character being preserved.
func unquoteToken(token string) string {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return token
	}

	s := token[1 : len(token)-1]

	var sb strings.Builder

	sb.Grow(len(s))

	for i := 0; i < len(s); i++ {
		char := s[i]
		if char == '\\' {
			i = handleEscapeSequence(&sb, s, i)
		} else {
			sb.WriteRune(rune(char))
		}
	}

	return sb.String()
}

// processCharForTokenization handles a single character during tokenization.
// It appends to currentToken and updates/returns inQuotes and escapeNextInQuote states.
func processCharForTokenization(char rune, currentToken *strings.Builder, inQuotes bool, escapeNextInQuote bool) (bool, bool) {
	if escapeNextInQuote {
		currentToken.WriteRune(char)

		return inQuotes, false // escapeNextInQuote is now false
	}

	if char == '\\' {
		currentToken.WriteRune(char)

		if inQuotes {
			return inQuotes, true // Next char in quote is escaped
		}

		return inQuotes, false // escapeNextInQuote remains false if not in quotes
	}

	if char == '"' {
		currentToken.WriteRune(char)
		return !inQuotes, false // Toggle inQuotes, reset escapeNextInQuote
	}

	// Regular character or whitespace within quotes
	if !unicode.IsSpace(char) || inQuotes {
		currentToken.WriteRune(char)
	}

	return inQuotes, false // escapeNextInQuote remains false
}

// tokenizeLine splits a line from a .netrc file into tokens.
// It respects double-quoted strings, treating them as single tokens (quotes included).
// Whitespace outside of quotes acts as a delimiter.
// Backslashes within quotes are preserved for unquoteToken to handle.
func tokenizeLine(line string) []string {
	var tokens []string

	var currentToken strings.Builder

	inQuotes := false
	escapeNextInQuote := false

	for _, char := range line {
		inQuotes, escapeNextInQuote = processCharForTokenization(char, &currentToken, inQuotes, escapeNextInQuote)

		// If not in quotes AND current char is a space AND token has content, finalize token
		if !inQuotes && unicode.IsSpace(char) && currentToken.Len() > 0 {
			// if we just exited quotes with this space, the quote char itself is part of currentToken
			// so we don't lose it.
			tokens = append(tokens, currentToken.String())
			currentToken.Reset()
		}
	}

	// Add the last token if there is any content left
	if currentToken.Len() > 0 {
		tokens = append(tokens, currentToken.String())
	}

	return tokens
}

// netrcParseState holds the current parsing state for a .netrc file.
type netrcParseState struct {
	activeMachine    string
	activeLogin      string
	activeLoginSet   bool
	inMachineContext bool
	inDefaultContext bool

	hostLogin    string
	hostPassword string
	hostFound    bool

	defaultLogin    string
	defaultPassword string
	defaultFound    bool

	targetHost string // The host we are looking for
}

// handleMachineToken processes the 'machine' keyword.
func (s *netrcParseState) handleMachineToken(value string) {
	s.inMachineContext = true
	s.inDefaultContext = false
	s.activeMachine = value
	s.activeLogin = ""
	s.activeLoginSet = false

	if s.activeMachine == s.targetHost {
		s.hostFound = true
	}
}

// handleDefaultToken processes the 'default' keyword.
func (s *netrcParseState) handleDefaultToken() {
	s.inMachineContext = false
	s.inDefaultContext = true
	s.activeMachine = ""
	s.activeLogin = ""
	s.activeLoginSet = false
	s.defaultFound = true
}

// handleLoginToken processes the 'login' or 'user' keyword.
func (s *netrcParseState) handleLoginToken(value string) {
	if !s.inMachineContext && !s.inDefaultContext {
		return // login/user outside machine/default context is ignored
	}

	s.activeLogin = value
	s.activeLoginSet = true

	if s.inMachineContext && s.activeMachine == s.targetHost {
		s.hostLogin = s.activeLogin
	} else if s.inDefaultContext {
		s.defaultLogin = s.activeLogin
	}
}

// handlePasswordToken processes the 'password' keyword.
func (s *netrcParseState) handlePasswordToken(value string) {
	if !s.activeLoginSet { // Password without preceding login/user
		return
	}

	if s.inMachineContext && s.activeMachine == s.targetHost {
		s.hostPassword = value
	} else if s.inDefaultContext {
		s.defaultPassword = value
	}
}

// processToken dispatches to specific handlers based on the keyword.
// It returns true if the provided value token was consumed by the keyword handler.
func (s *netrcParseState) processToken(keyword, value string, valueExists bool) (tokenConsumedValue bool) {
	lowerKeyword := strings.ToLower(keyword)

	switch lowerKeyword {
	case "machine", "login", "user", "password":
		if !valueExists {
			return false // These keywords require a value
		}
		// Initialize and unquote processedValue only when it's certain to be used for these cases.
		processedValue := unquoteToken(value)

		switch lowerKeyword {
		case "machine":
			s.handleMachineToken(processedValue)
		case "login", "user":
			s.handleLoginToken(processedValue)
		case "password":
			s.handlePasswordToken(processedValue)
		}

		return true // Value was consumed

	case "default":
		s.handleDefaultToken()

		return false // Default does not consume a value

	case "macdef":
		// macdef is not supported, effectively skip it and its definition body
		s.inMachineContext = false
		s.inDefaultContext = false
		s.activeMachine = ""

		return false // macdef itself does not consume the value token

	default:
		// Unknown keyword, ignore
		return false
	}
}

// processNetrcLine tokenizes and processes a single line from a .netrc file,
// updating the parse state. It returns true if the target host was found during
// the processing of this line.
func processNetrcLine(line string, state *netrcParseState) (hostFoundOnLine bool) {
	tokens := tokenizeLine(line)

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		value := ""
		valueExists := false
		if i+1 < len(tokens) {
			value = tokens[i+1]
			valueExists = true
		}

		if state.processToken(token, value, valueExists) {
			i++ // Advance token index because processToken consumed the value part.
		}

		if state.hostFound && state.activeMachine == state.targetHost && state.hostLogin != "" && state.hostPassword != "" {
			return true
		}
	}

	return false // Target host not found or not fully processed on this line
}

// ParseNetrcFile parses .netrc file content and returns credentials for the given host.
// It aims to follow common .netrc conventions, including handling of 'machine', 'default',
// 'login', 'password' keywords, quoted strings with escapes, and skipping comments/macdef.
// The first complete 'machine' entry matching targetHost wins.
// If no specific machine matches, the first complete 'default' entry wins.
func ParseNetrcFile(content string, targetHost string) (login, password string, found bool, err error) {
	state := &netrcParseState{targetHost: targetHost}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		if processNetrcLine(trimmedLine, state) {
			// If host was found and processed on this line with its credentials,
			// and we are strictly looking for the first match, we could break here.
			// However, processing all lines allows for the last definition of a machine/default to win,
			// which is a common behavior.
		}
	}

	if state.hostFound && state.hostLogin != "" && state.hostPassword != "" {
		return state.hostLogin, state.hostPassword, true, nil
	}

	if state.defaultFound && state.defaultLogin != "" && state.defaultPassword != "" {
		return state.defaultLogin, state.defaultPassword, true, nil
	}
	return "", "", false, nil
}
