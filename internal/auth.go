package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

type AuthResponse struct {
	VerificationUri string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	Interval        int    `json:"interval"`
}

type AuthSession struct {
	ClientId string
	Response *AuthResponse
	Nonce    string
}

type PollResponse struct {
	// AccessToken is the primary token used to access protected resources.
	AccessToken string `json:"access_token"`

	// ExpiresIn is the lifetime in seconds of the access token.
	ExpiresIn int `json:"expires_in"`

	// TokenType is typically "Bearer".
	TokenType string `json:"token_type"`

	// Scope lists the authorized scopes granted to this token.
	Scope string `json:"scope"`

	// RefreshToken is used to obtain a new access token when the current one expires.
	RefreshToken string `json:"refresh_token"`

	// IDToken is the OpenID Connect token containing user identity claims.
	IDToken string `json:"id_token,omitempty"`

	Nonce string `json:"nonce,omitempty"`
}

type PollError struct {
	ErrorReason string `json:"error"`
}

func (e PollError) Error() string {
	return e.ErrorReason
}

// codeChallenge generates a codeChallenge and codeVerifier string (RFC 7636) that can be used to obtain a token
func generateCodeChallenge() (string, string, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(83))
	if err != nil {
		return "", "", err
	}
	codeVerifierLength := nBig.Int64()
	codeVerifierBytes := make([]byte, codeVerifierLength)
	_, err = rand.Read(codeVerifierBytes)
	if err != nil {
		return "", "", nil
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	codeChallengeDigest := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeDigest[:])

	return codeVerifier, codeChallenge, nil
}

// generateNonce generates a

func authorize(reqUrl string, clientId string, openid bool) (*AuthSession, error) {
	// Need to contact the server with code challenge, then get the code in response, and then return the code
	var authSession AuthSession

	_, nonce, err := generateCodeChallenge()
	if err != nil {
		return nil, err
	}

	authSession.ClientId = clientId
	authSession.Nonce = nonce

	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("nonce", nonce)
	if openid {
		data.Set("scopes", "openid read write")
	} else {
		data.Set("scopes", "read write")
	}

	req, err := http.NewRequest(http.MethodPost, reqUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Bad Response Status: %s", resp.Status)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var authData AuthResponse
	err = json.Unmarshal(bodyBytes, &authData)
	if err != nil {
		return nil, err
	}

	authSession.Response = &authData
	return &authSession, nil
}

func requestToken() error {
	return nil
}

func poll(reqUrl string, deviceCode string, clientId string, nonce string) (bool, *PollResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequest(http.MethodPost, reqUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// b, _ := req.GetBody()
	// defer b.Close()
	// d, _ := io.ReadAll(b)
	// fmt.Printf("Request data: %s", d)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var pollError PollError
		err = json.Unmarshal(bodyBytes, &pollError)
		if err != nil {
			return false, nil, err
		}
		if pollError.ErrorReason == "authorization_pending" {
			return false, nil, nil
		}
		return false, nil, pollError
	}

	var pollResponse PollResponse
	err = json.Unmarshal(bodyBytes, &pollResponse)
	if err != nil {
		return false, nil, err
	}
	if pollResponse.Nonce != nonce {
		return false, nil, fmt.Errorf("Nonce recieved from token exchange does not match initial request")
	}

	return true, &pollResponse, nil
}
