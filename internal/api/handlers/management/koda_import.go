package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	kodaauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/koda"
	log "github.com/sirupsen/logrus"
)

type kodaImportRequest struct {
	// CredentialsPath is the path to the KodaCode CLI credentials.json file.
	// Defaults to ~/.kodacode/credentials.json if empty.
	CredentialsPath string `json:"credentials_path"`
}

// ImportKodaCredential reads a KodaCode CLI credentials.json and saves
// the access token as a new auth file in the auth directory.
//
// Endpoint:
//
//	POST /v0/management/koda-import
//
// Request JSON:
//   - credentials_path (optional): path to credentials.json.
//     Defaults to ~/.kodacode/credentials.json.
//
// Response:
//   - {"status":"ok","file":"koda-<email>.json","email":"...","tier":"..."}
func (h *Handler) ImportKodaCredential(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}

	var credPath string
	var creds *kodaauth.KodaCredentialsFile
	var err error

	// 1. Try to read from uploaded file
	file, err := c.FormFile("file")
	if err == nil && file != nil {
		log.Infof("koda-import: parsing uploaded credentials file")
		openedFile, err := file.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": "error",
				"error":  fmt.Sprintf("failed to open uploaded file: %v", err),
			})
			return
		}
		defer openedFile.Close()

		creds = &kodaauth.KodaCredentialsFile{}
		if err := json.NewDecoder(openedFile).Decode(creds); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": "error",
				"error":  fmt.Sprintf("failed to decode uploaded JSON: %v", err),
			})
			return
		}

	} else {
		// 2. Try to read from JSON payload credentials_path, then default
		var req kodaImportRequest
		_ = c.ShouldBindJSON(&req)

		credPath = strings.TrimSpace(req.CredentialsPath)
		if credPath == "" {
			credPath = c.PostForm("credentials_path")
		}
		credPath = strings.TrimSpace(credPath)
		if credPath == "" {
			credPath = kodaauth.DefaultCredentialsPath
		}

		log.Infof("koda-import: reading credentials from %s", credPath)
		creds, err = kodaauth.LoadCredentialsFile(credPath)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": "error",
				"error":  fmt.Sprintf("failed to read credentials: %v", err),
			})
			return
		}
	}

	accessToken := strings.TrimSpace(creds.KodaAuth.AccessToken)
	if accessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "credentials file has empty accessToken",
		})
		return
	}

	email := strings.TrimSpace(creds.KodaAuth.User.Email)
	tier := strings.TrimSpace(creds.KodaAuth.Tier)
	expiresAt := strings.TrimSpace(creds.KodaAuth.ExpiresAt)

	ts := &kodaauth.KodaTokenStorage{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
		Email:       email,
		Tier:        tier,
		Type:        "koda",
	}

	authDir := strings.TrimSpace(h.cfg.AuthDir)
	if authDir == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  "auth dir not configured",
		})
		return
	}

	if err = os.MkdirAll(authDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("failed to create auth dir: %v", err),
		})
		return
	}

	fileName := kodaauth.CredentialFileName(email)
	filePath := filepath.Join(authDir, fileName)

	// Marshal the token and write to auth dir.
	data, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("failed to serialize token: %v", err),
		})
		return
	}

	if err = os.WriteFile(filePath, data, 0o600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("failed to write credential file: %v", err),
		})
		return
	}

	log.Infof("koda-import: credential saved to %s", filePath)

	// Register the auth file with the running auth manager.
	if err = h.registerAuthFromFile(c.Request.Context(), filePath, data); err != nil {
		log.Warnf("koda-import: registerAuthFromFile failed (file was written): %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"file":      fileName,
		"email":     email,
		"tier":      tier,
		"expiresAt": expiresAt,
	})
}
