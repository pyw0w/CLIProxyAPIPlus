package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/koda"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// KodaAuthenticator implements the login flow for KodaCode accounts.
// It reads the existing CLI credentials.json rather than initiating a new OAuth flow.
type KodaAuthenticator struct{}

// NewKodaAuthenticator constructs a KodaCode authenticator.
func NewKodaAuthenticator() *KodaAuthenticator {
	return &KodaAuthenticator{}
}

// Provider returns the provider identifier for koda.
func (a *KodaAuthenticator) Provider() string {
	return "koda"
}

// RefreshLead returns nil because KodaCode tokens don't have a refresh mechanism here.
func (a *KodaAuthenticator) RefreshLead() *time.Duration {
	return nil
}

// Login reads the KodaCode CLI credentials file and saves the token to the auth directory.
// The path to credentials.json can be provided via opts.Metadata["credentials_path"].
// Defaults to ~/.kodacode/credentials.json.
func (a *KodaAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("koda auth: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	// Determine the credentials file path.
	credPath := koda.DefaultCredentialsPath
	if opts.Metadata != nil {
		if p, ok := opts.Metadata["credentials_path"]; ok && strings.TrimSpace(p) != "" {
			credPath = strings.TrimSpace(p)
		}
	}

	// Allow the user to specify the path interactively.
	if opts.Prompt != nil {
		promptedPath, err := opts.Prompt(fmt.Sprintf("Path to KodaCode credentials.json [%s]: ", credPath))
		if err == nil && strings.TrimSpace(promptedPath) != "" {
			credPath = strings.TrimSpace(promptedPath)
		}
	}

	fmt.Printf("Reading KodaCode credentials from: %s\n", credPath)

	creds, err := koda.LoadCredentialsFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("koda auth: %w", err)
	}

	accessToken := strings.TrimSpace(creds.KodaAuth.AccessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("koda auth: credentials file has empty accessToken")
	}

	email := strings.TrimSpace(creds.KodaAuth.User.Email)
	tier := strings.TrimSpace(creds.KodaAuth.Tier)
	expiresAt := strings.TrimSpace(creds.KodaAuth.ExpiresAt)

	ts := &koda.KodaTokenStorage{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
		Email:       email,
		Tier:        tier,
		Type:        "koda",
	}

	fileName := koda.CredentialFileName(email)

	metadata := map[string]any{
		"type":         "koda",
		"accessToken":  accessToken,
		"expiresAt":    expiresAt,
		"email":        email,
		"tier":         tier,
		"timestamp":    time.Now().UnixMilli(),
	}

	label := "koda"
	if email != "" {
		label = email
	}

	fmt.Printf("KodaCode authentication imported for %s (tier: %s)\n", label, tier)

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    label,
		Storage:  ts,
		Metadata: metadata,
	}, nil
}
