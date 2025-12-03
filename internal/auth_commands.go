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

func Login(ctx context.Context, openid bool) error {
	// authorize
	cfg := ctx.Value(config.ConfigKey).(config.Config)
	reqUrl := cfg.BaseURL + cfg.AuthEndpoint
	authSession, err := authorize(reqUrl, cfg.ClientId, openid)
	if err != nil {
		return err
	}
	// display auth link
	fmt.Printf("Please visit %s to validate this device\n", authSession.Response.VerificationUri)
	fmt.Printf("Enter User Code %s in the link above\n", authSession.Response.UserCode)
	// poll
	var finalResponse *PollResponse
	pollUrl := cfg.BaseURL + cfg.TokenEndpoint	
	for { 
		ok, pollResponse, err := poll(pollUrl, authSession.Response.DeviceCode, cfg.ClientId, authSession.Nonce)
		if ok {
			finalResponse = pollResponse
			break
		}
		if err != nil {
			return err
		}
		time.Sleep(10*time.Second)
	}
	// 
	fmt.Print(finalResponse.IDToken)
	userHome, _ := os.UserHomeDir()
	tokenFile := filepath.Join(userHome, vars.CliCommand, "token")
	f, err := os.Create(tokenFile)
	if err != nil {
		return err
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
