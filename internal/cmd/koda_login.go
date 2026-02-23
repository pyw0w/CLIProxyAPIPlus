package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
)

// DoKodaLogin imports the KodaCode CLI credentials and saves them to the auth directory.
// It reads the existing credentials.json from the KodaCode CLI instead of starting
// a new OAuth flow, since the token is already available in the CLI's credential store.
//
// Parameters:
//   - cfg: The application configuration
//   - options: Login options including credentials file path and prompts
func DoKodaLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	manager := newAuthManager()

	promptFn := options.Prompt
	if promptFn == nil {
		promptFn = func(prompt string) (string, error) {
			fmt.Print(prompt)
			var value string
			fmt.Scanln(&value)
			return strings.TrimSpace(value), nil
		}
	}

	authOpts := &sdkAuth.LoginOptions{
		NoBrowser:    options.NoBrowser,
		CallbackPort: options.CallbackPort,
		Metadata:     map[string]string{},
		Prompt:       promptFn,
	}

	_, savedPath, err := manager.Login(context.Background(), "koda", cfg, authOpts)
	if err != nil {
		fmt.Printf("KodaCode authentication failed: %v\n", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}

	fmt.Println("KodaCode authentication imported successfully!")
}
