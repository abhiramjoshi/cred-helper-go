package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abhiramjoshi/cred-helper-go/pkg/config"
	"github.com/abhiramjoshi/cred-helper-go/pkg/vars"
)

// TestGenerateCodeChallenge validates the PKCE challenge generation.
func TestGenerateCodeChallenge(t *testing.T) {
	verifier, challenge, err := generateCodeChallenge()
	if err != nil {
		t.Fatalf("generateCodeChallenge failed: %v", err)
	}

	// 1. Check verifier/challenge are non-empty
	if verifier == "" || challenge == "" {
		t.Errorf("Verifier or Challenge is empty. Verifier: %s, Challenge: %s", verifier, challenge)
	}

	// 2. Check the code challenge is the SHA256 base64-URL-encoded digest of the verifier
	digest := sha256.Sum256([]byte(verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(digest[:])

	if challenge != expectedChallenge {
		t.Errorf("Code Challenge mismatch.\nGot: %s\nWant: %s", challenge, expectedChallenge)
	}

	// 3. Check for valid characters (base64-url encoding)
	if strings.ContainsAny(challenge, "+/=") || strings.ContainsAny(verifier, "+/=") {
		t.Errorf("Generated strings contain illegal characters for base64-url encoding.")
	}
}

// TestAuthorize uses a mock server to test success and failure cases of the authorize function.
func TestAuthorize(t *testing.T) {
	const mockClientId = "test_client"

	tests := []struct {
		name             string
		status           int
		body             AuthResponse
		mockError        string
		expectSuccess    bool
		expectedUserCode string
	}{
		{
			name:   "Success",
			status: http.StatusOK,
			body: AuthResponse{
				VerificationUri: "https://auth.example.com/verify",
				UserCode:        "A1B2C3D4",
				DeviceCode:      "E5F6G7H8",
				Interval:        5,
			},
			expectSuccess:    true,
			expectedUserCode: "A1B2C3D4",
		},
		{
			name:          "HTTP Error 400",
			status:        http.StatusBadRequest,
			mockError:     "Bad Request",
			expectSuccess: false,
		},
		{
			name:          "Invalid JSON Response",
			status:        http.StatusOK,
			mockError:     "}{", // Invalid JSON
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Errorf("Expected Content-Type 'application/x-www-form-urlencoded', got %s", r.Header.Get("Content-Type"))
				}

				if tt.mockError != "" && tt.status == http.StatusOK {
					// Test case for invalid JSON response
					w.WriteHeader(tt.status)
					io.WriteString(w, tt.mockError)
					return
				}

				w.WriteHeader(tt.status)
				if tt.status == http.StatusOK {
					respBody, _ := json.Marshal(tt.body)
					io.WriteString(w, string(respBody))
				} else if tt.mockError != "" {
					io.WriteString(w, tt.mockError)
				}
			}))
			defer server.Close()

			authResponse, err := authorize(server.URL, mockClientId)

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("Expected success, but got error: %v", err)
				}
				if authResponse == nil {
					t.Fatal("Expected AuthResponse, but got nil")
				}
				if authResponse.UserCode != tt.expectedUserCode {
					t.Errorf("UserCode mismatch. Got: %s, Want: %s", authResponse.UserCode, tt.expectedUserCode)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected error, but got success with response: %+v", authResponse)
				}
			}
		})
	}
}

// TestPoll tests the polling function for token retrieval, including authorization_pending and errors.
func TestPoll(t *testing.T) {
	const (
		mockClientId   = "test_client"
		mockDeviceCode = "device-123"
	)

	successResponse := PollResponse{
		AccessToken:  "mock_access_token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		Scope:        "test",
		RefreshToken: "mock_refresh_token",
	}

	tests := []struct {
		name                string
		status              int
		responseBody        interface{} // Either PollResponse or PollError
		expectOK            bool
		expectError         bool
		expectedErrorReason string
	}{
		{
			name:         "Success",
			status:       http.StatusOK,
			responseBody: successResponse,
			expectOK:     true,
			expectError:  false,
		},
		{
			name:                "Authorization Pending",
			status:              http.StatusBadRequest,
			responseBody:        PollError{ErrorReason: "authorization_pending"},
			expectOK:            false,
			expectError:         false, // Special case: authorization_pending is expected behavior, not an error
			expectedErrorReason: "authorization_pending",
		},
		{
			name:                "Access Denied Error",
			status:              http.StatusBadRequest,
			responseBody:        PollError{ErrorReason: "access_denied"},
			expectOK:            false,
			expectError:         true,
			expectedErrorReason: "access_denied",
		},
		{
			name:                "Expired Token Error",
			status:              http.StatusBadRequest,
			responseBody:        PollError{ErrorReason: "expired_token"},
			expectOK:            false,
			expectError:         true,
			expectedErrorReason: "expired_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				w.WriteHeader(tt.status)
				respBody, _ := json.Marshal(tt.responseBody)
				io.WriteString(w, string(respBody))

				// Check posted data
				r.ParseForm()
				if r.Form.Get("client_id") != mockClientId {
					t.Errorf("Expected client_id '%s', got '%s'", mockClientId, r.Form.Get("client_id"))
				}
				if r.Form.Get("device_code") != mockDeviceCode {
					t.Errorf("Expected device_code '%s', got '%s'", mockDeviceCode, r.Form.Get("device_code"))
				}
			}))
			defer server.Close()

			ok, pollResponse, err := poll(server.URL, mockDeviceCode, mockClientId)

			if ok != tt.expectOK {
				t.Errorf("Expected ok=%t, got ok=%t", tt.expectOK, ok)
			}

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, but got nil")
				}
				// Check if the error reason matches the expected PollError
				if pollErr, isPollErr := err.(PollError); isPollErr {
					if pollErr.ErrorReason != tt.expectedErrorReason {
						t.Errorf("Expected error reason '%s', got '%s'", tt.expectedErrorReason, pollErr.ErrorReason)
					}
				} else {
					t.Errorf("Expected PollError, got different error type: %v", err)
				}
			} else if !tt.expectOK && tt.expectedErrorReason == "authorization_pending" {
				// Special check for authorization_pending (non-error, non-OK)
				if err != nil {
					t.Errorf("Expected nil error for authorization_pending, got: %v", err)
				}
				if pollResponse != nil {
					t.Errorf("Expected nil PollResponse for authorization_pending, got: %+v", pollResponse)
				}
			} else if tt.expectOK {
				if err != nil {
					t.Fatalf("Expected success, but got error: %v", err)
				}
				if pollResponse.AccessToken != successResponse.AccessToken {
					t.Errorf("AccessToken mismatch. Got: %s, Want: %s", pollResponse.AccessToken, successResponse.AccessToken)
				}
			}
		})
	}
}

// TestLogin_Success mocks the entire device flow and ensures the token is saved.
func TestLogin_Success(t *testing.T) {
	// Mock the home directory to prevent actual file writing to user's system
	t.Setenv("HOME", t.TempDir())

	// Use a channel to simulate the state machine for polling
	pollAttempt := make(chan int, 1)
	pollAttempt <- 0 // Initial state

	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentAttempt := <-pollAttempt
		pollAttempt <- currentAttempt + 1

		switch r.URL.Path {
		case "/auth":
			w.WriteHeader(http.StatusOK)
			resp := AuthResponse{
				VerificationUri: "https://mock.auth.url",
				ExpiresIn:       600,
				UserCode:        "MOCKCODE",
				DeviceCode:      "MOCKDEVICE",
				Interval:        1,
			}
			json.NewEncoder(w).Encode(resp)

		case "/token":
			if currentAttempt < 2 {
				// Simulate "authorization_pending" for the first two polls
				w.WriteHeader(http.StatusBadRequest)
				resp := PollError{ErrorReason: "authorization_pending"}
				json.NewEncoder(w).Encode(resp)
			} else {
				// Third poll succeeds
				w.WriteHeader(http.StatusOK)
				resp := PollResponse{
					AccessToken:  "MOCK_ACCESS_TOKEN",
					IDToken:      "MOCK_JWT_TOKEN",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					RefreshToken: "MOCK_REFRESH",
				}
				json.NewEncoder(w).Encode(resp)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Mock configuration
	cfg := config.Config{
		BaseURL:       server.URL,
		AuthEndpoint:  "/auth",
		TokenEndpoint: "/token",
		ClientId:      "mock_client_id",
	}

	// Create context with mock config
	ctx := context.WithValue(context.Background(), config.ConfigKey, cfg)

	// Suppress standard output for a cleaner test run
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run Login
	err := Login(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = originalStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("Login failed with error: %v", err)
	}

	// Check CLI output for user instructions
	output := string(out)
	if !strings.Contains(output, "MOCKCODE") {
		t.Errorf("CLI output did not contain user code. Got:\n%s", output)
	}

	// Check if the token file was created and contains the correct data
	userHome, _ := os.UserHomeDir()
	tokenFile := filepath.Join(userHome, vars.CliCommand, "token")

	// Since the original Login implementation uses hardcoded time.Sleep(10*time.Second),
	// we must use a minimal, functional implementation here. In a real application,
	// you'd mock the time.Sleep to ensure the test finishes quickly.
	// We rely on the mock server logic above to break the loop after 3 attempts.

	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}
	if string(tokenBytes) != "MOCK_JWT_TOKEN" {
		t.Errorf("Token file content mismatch. Got: '%s', Want: 'MOCK_JWT_TOKEN'", string(tokenBytes))
	}

	// Ensure the loop ran 3 times (1 initial + 2 pending + 1 success)
	finalAttempt := <-pollAttempt
	if finalAttempt != 3 {
		t.Errorf("Expected 3 poll attempts (0, 1, 2), got %d", finalAttempt)
	}
}
