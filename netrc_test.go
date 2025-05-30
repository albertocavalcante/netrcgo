package netrc_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	netrc "github.com/albertocavalcante/netrcgo"
	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"github.com/stretchr/testify/require"
)

const (
	// NetrcFilePermissions defines the secure permissions for .netrc files (0600).
	NetrcFilePermissions = 0o600
)

// CreateTemporaryNetrc creates a temporary .netrc file with the specified content.
// The file is created with 0600 permissions for security.
func CreateTemporaryNetrc(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, ".netrc")
	require.NoError(t, os.WriteFile(file, []byte(content), NetrcFilePermissions))

	return file
}

// WithEnv temporarily sets environment variables for the duration of a test function.
// It automatically restores the original values when the test completes.
func WithEnv(t *testing.T, env map[string]string, fn func()) {
	t.Helper()
	// Save originals
	orig := make(map[string]string, len(env))
	for k := range env {
		orig[k] = os.Getenv(k)

		if env[k] == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, env[k])
		}
	}

	t.Cleanup(func() {
		for k, v := range orig {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	})
	fn()
}

func TestParseNetrcScenarios(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		host        string
		expectLogin string
		expectPass  string
		expectFound bool
		expectErr   bool
	}{
		{
			name:        "basic machine entry",
			filename:    "basic_entry.netrc",
			host:        "example.com",
			expectLogin: "user1",
			expectPass:  "pass1",
			expectFound: true,
		},
		{
			name:        "host not found in basic_entry",
			filename:    "basic_entry.netrc",
			host:        "other.com",
			expectFound: false,
		},
		{
			name:        "default only",
			filename:    "default_only.netrc",
			host:        "anyhost.com",
			expectLogin: "default_user",
			expectPass:  "default_pass",
			expectFound: true,
		},
		{
			name:        "machine overrides default",
			filename:    "machine_overrides_default.netrc",
			host:        "override.com",
			expectLogin: "specific_user",
			expectPass:  "specific_pass",
			expectFound: true,
		},
		{
			name:        "default fallback when machine not found",
			filename:    "machine_overrides_default.netrc",
			host:        "another.com",
			expectLogin: "default_user",
			expectPass:  "default_pass",
			expectFound: true,
		},
		{
			name:        "multiple machines - host1",
			filename:    "multiple_entries.netrc",
			host:        "host1.com",
			expectLogin: "user_h1",
			expectPass:  "pass_h1",
			expectFound: true,
		},
		{
			name:        "multiple machines - host2",
			filename:    "multiple_entries.netrc",
			host:        "host2.com",
			expectLogin: "user_h2",
			expectPass:  "pass_h2",
			expectFound: true,
		},
		{
			name:        "comments and whitespace - spaced.com",
			filename:    "comments_and_whitespace.netrc",
			host:        "spaced.com",
			expectLogin: "user_sw",
			expectPass:  "pass_sw",
			expectFound: true,
		},
		{
			name:        "comments and whitespace - normal.com",
			filename:    "comments_and_whitespace.netrc",
			host:        "normal.com",
			expectLogin: "user_n",
			expectPass:  "pass_n",
			expectFound: true,
		},
		{
			name:        "quoted credentials with spaces",
			filename:    "quoted_values.netrc",
			host:        "ftp server alpha",
			expectLogin: "user with spaces",
			expectPass:  "my secret password",
			expectFound: true,
		},
		{
			name:        "quoted credentials - simple",
			filename:    "quoted_values.netrc",
			host:        "anotherserver.com",
			expectLogin: "simpleuser",
			expectPass:  "simplepass",
			expectFound: true,
		},
		{
			name:        "extended keywords - server one",
			filename:    "extended_keywords.netrc",
			host:        "server.one",
			expectLogin: "user_one",
			expectPass:  "pass_one",
			expectFound: true,
		},
		{
			name:        "incomplete entry - no_login.com",
			filename:    "incomplete_entry.netrc",
			host:        "no_login.com",
			expectFound: false,
		},
		{
			name:        "incomplete entry - no_pass.com",
			filename:    "incomplete_entry.netrc",
			host:        "no_pass.com",
			expectFound: false,
		},
		{
			name:        "incomplete entry - full_entry.com",
			filename:    "incomplete_entry.netrc",
			host:        "full_entry.com",
			expectLogin: "user_fe",
			expectPass:  "pass_fe",
			expectFound: true,
		},
		{
			name:        "empty file",
			filename:    "empty_file.netrc",
			host:        "example.com",
			expectFound: false,
		},
		{
			name:        "keywords case insensitive - machine",
			filename:    "keywords_case_insensitive.netrc",
			host:        "case.com",
			expectLogin: "UserCase",
			expectPass:  "PassCase",
			expectFound: true,
		},
		{
			name:        "keywords case insensitive - default",
			filename:    "keywords_case_insensitive.netrc",
			host:        "anyother.com",
			expectLogin: "DefUser",
			expectPass:  "DefPass",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use Bazel runfiles to access test data
			testdataPath, err := bazel.Runfile("testdata/" + tt.filename)
			if err != nil {
				t.Fatal(err)
			}

			contentBytes, err := os.ReadFile(testdataPath)
			require.NoError(t, err, "Failed to read testdata file: %s", tt.filename)
			content := string(contentBytes)

			login, pass, found, err := netrc.ParseNetrcFile(content, tt.host)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectFound, found)

				if tt.expectFound {
					require.Equal(t, tt.expectLogin, login)
					require.Equal(t, tt.expectPass, pass)
				}
			}
		})
	}
}

func TestGetHostCredentials(t *testing.T) {
	content := "machine example.com login testuser password testpass"
	netrcPath := CreateTemporaryNetrc(t, content)

	WithEnv(t, map[string]string{"NETRC": netrcPath}, func() {
		creds, found, err := netrc.GetHostCredentials("example.com")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, "testuser", creds.Login)
		require.Equal(t, "testpass", creds.Password)
	})
}

func TestNonExistentFile(t *testing.T) {
	f, err := netrc.NewFile(filepath.Join(t.TempDir(), "nonexistent"))
	require.NoError(t, err)

	creds, found, err := f.GetCredentials("example.com")
	require.NoError(t, err)
	require.False(t, found)
	require.True(t, creds.IsEmpty())
}

func TestFilePermissionValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission test on Windows")
	}

	content := "machine example.com login user password pass"
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, ".netrc")
	require.NoError(t, os.WriteFile(netrcPath, []byte(content), 0o644))

	f, err := netrc.NewFile(netrcPath)
	require.NoError(t, err)

	_, _, err = f.GetCredentials("example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "insecure permissions")
}

func TestInputValidation(t *testing.T) {
	content := "machine example.com login user password pass"
	netrcPath := CreateTemporaryNetrc(t, content)

	f, err := netrc.NewFile(netrcPath)
	require.NoError(t, err)

	_, _, err = f.GetCredentials("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "host cannot be empty")
}

func TestDefaultPath(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "NETRC environment variable",
			env:  map[string]string{"NETRC": "/custom/.netrc", "HOME": "", "USERPROFILE": ""},
			want: "/custom/.netrc",
		},
		{
			name: "HOME fallback",
			env:  map[string]string{"NETRC": "", "HOME": "/home/user", "USERPROFILE": ""},
			want: filepath.Join("/home/user", ".netrc"),
		},
		{
			name: "USERPROFILE fallback",
			env:  map[string]string{"NETRC": "", "HOME": "", "USERPROFILE": "/Users/user"},
			want: filepath.Join("/Users/user", ".netrc"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			WithEnv(t, tt.env, func() {
				path, err := netrc.DefaultPath()
				require.NoError(t, err)
				require.Equal(t, tt.want, path)
			})
		})
	}
}
