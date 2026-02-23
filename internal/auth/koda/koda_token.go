// Package koda provides authentication and token management functionality
// for KodaCode services. It supports reading existing credentials from the
// KodaCode CLI credentials.json file format.
package koda

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	log "github.com/sirupsen/logrus"
)

const (
	// AuthBaseURL is the KodaCode authentication server URL.
	AuthBaseURL = "https://auth.kodacode.ru"
	// APIBaseURL is the KodaCode API base URL (OpenAI-compatible).
	APIBaseURL = "https://api.kodacode.ru/v1"
	// DefaultCredentialsPath is the default path to the KodaCode CLI credentials file.
	DefaultCredentialsPath = "~/.config/koda/credentials.json"
)

// KodaTokenStorage stores token information for KodaCode authentication.
type KodaTokenStorage struct {
	// AccessToken is the KodaCode access token.
	AccessToken string `json:"accessToken"`
	// ExpiresAt is the RFC3339 timestamp when the token expires.
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Email is the email address of the authenticated user.
	Email string `json:"email,omitempty"`
	// Tier indicates the subscription tier (e.g. "Free").
	Tier string `json:"tier,omitempty"`
	// Type indicates the authentication provider type, always "koda" for this storage.
	Type string `json:"type"`
}

// SaveTokenToFile serializes the KodaCode token storage to a JSON file.
func (ts *KodaTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "koda"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Errorf("failed to close file: %v", errClose)
		}
	}()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(ts); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}

// CredentialFileName returns the filename used to persist KodaCode credentials.
func CredentialFileName(email string) string {
	if email == "" {
		return "koda-default.json"
	}
	return fmt.Sprintf("koda-%s.json", email)
}

// KodaCredentialsFile represents the top-level structure of the KodaCode CLI credentials.json file.
type KodaCredentialsFile struct {
	KodaAuth KodaAuthEntry `json:"kodaAuth"`
}

// KodaAuthEntry holds the auth entry nested inside credentials.json.
type KodaAuthEntry struct {
	AccessToken string      `json:"accessToken"`
	ExpiresAt   string      `json:"expiresAt"`
	BaseURL     string      `json:"baseUrl"`
	DeviceCode  string      `json:"deviceCode"`
	ID          string      `json:"id"`
	Linked      bool        `json:"linked"`
	Tier        string      `json:"tier"`
	Usage       KodaUsage   `json:"usage"`
	User        KodaUser    `json:"user"`
}

// KodaUsage represents the usage limits from KodaCode.
type KodaUsage struct {
	Remaining int    `json:"remaining"`
	Max       int    `json:"max"`
	Period    string `json:"period"`
}

// KodaUser represents the user profile from KodaCode.
type KodaUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Label     string `json:"label"`
}

// LoadCredentialsFile attempts to read the KodaCode CLI credentials.json file
// from the provided path (tildes are expanded).
func LoadCredentialsFile(path string) (*KodaCredentialsFile, error) {
	resolved := resolvePath(path)
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("koda: failed to read credentials file %s: %w", resolved, err)
	}
	var creds KodaCredentialsFile
	if err = json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("koda: failed to parse credentials file: %w", err)
	}
	return &creds, nil
}

// resolvePath expands a leading ~ to the user home directory.
func resolvePath(path string) string {
	if len(path) > 1 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}
