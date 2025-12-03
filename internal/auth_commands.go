package internal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/abhiramjoshi/cred-helper-go/pkg/config"
	"github.com/abhiramjoshi/cred-helper-go/pkg/vars"
)

// ANSI Color Codes:
const (
    ColorReset  = "\033[0m"
    ColorRed    = "\033[31m"
    ColorGreen  = "\033[32m"
    ColorYellow = "\033[33m"
    ColorBlue   = "\033[34m"
    StyleBold   = "\033[1m"
)

func Login(ctx context.Context, openid bool) error {
	// authorize
	cfg := ctx.Value(config.ConfigKey).(config.Config)
	reqUrl := cfg.BaseURL + cfg.AuthEndpoint
	authSession, err := authorize(ctx, reqUrl, cfg.ClientId, openid)
	if err != nil {
		return err
	}
	// display auth link
	fmt.Printf("\n--- Device Verification Required ---\n")
	fmt.Printf("🌐 Please visit %s%s%s to validate this device.\n", ColorBlue, authSession.Response.VerificationUri, ColorReset)
  fmt.Printf("🔑 Enter User Code: %s%s%s in the link above.\n", StyleBold, authSession.Response.UserCode, ColorReset)
	fmt.Printf("----------------------------------\n\n")
	// poll
	var finalResponse *PollResponse
	pollUrl := cfg.BaseURL + cfg.TokenEndpoint	
	for { 
		ok, pollResponse, err := poll(ctx, pollUrl, authSession.Response.DeviceCode, cfg.ClientId, authSession.Nonce)
		if ok {
			finalResponse = pollResponse
			break
		}
		if err != nil {
			return err
		}
		time.Sleep(1*time.Second)
	}
	//
	fmt.Printf("🔑 Your Token:\n")
	fmt.Println(finalResponse.IDToken)
	userHome, _ := os.UserHomeDir()
	tokenDir := filepath.Join(userHome, fmt.Sprintf(".%s", vars.CliCommand))
	tokenFile := filepath.Join(tokenDir, "token")
	err = os.MkdirAll(tokenDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Error saving token locally: %s", err)
	}	
	f, err := os.Create(tokenFile)
	if err != nil {
		return fmt.Errorf("Error saving token locally: %s", err)
	}
	defer f.Close()
	// Save final authtoken and JWT token to file
	f.WriteString(finalResponse.IDToken)
	return nil
}

func Refresh(ctx context.Context) error {
	// authorize
	// gettoken
	// poll
	return nil
}
