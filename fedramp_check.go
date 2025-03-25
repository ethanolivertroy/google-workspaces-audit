package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	reports "google.golang.org/api/reports/v1"

	// Optional imports for different credential methods
	// Comment out if not needed
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"net/url"
)

// Configuration settings
type Config struct {
	CredentialsPath    string   `json:"credentials_path"`
	TokenPath          string   `json:"token_path"`
	ReportOutputPath   string   `json:"report_output_path"`
	Scopes             []string `json:"scopes"`
	AuthMethod         string   `json:"auth_method"`
	AdminEmail         string   `json:"admin_email"`
	ServiceAccountPath string   `json:"service_account_path"`
	GCPSecretName      string   `json:"gcp_secret_name"`
	GCPSecretProject   string   `json:"gcp_secret_project"`
	AWSSecretName      string   `json:"aws_secret_name"`
	AWSRegion          string   `json:"aws_region"`
	VaultAddress       string   `json:"vault_address"`
	VaultToken         string   `json:"vault_token"`
	VaultPath          string   `json:"vault_path"`
}

// Check represents a FedRAMP compliance check
type Check struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Details     string `json:"details"`
	FixSteps    string `json:"fix_steps"`
}

// ComplianceReport represents the full FedRAMP compliance report
type ComplianceReport struct {
	Timestamp       string   `json:"timestamp"`
	DomainName      string   `json:"domain_name"`
	Edition         string   `json:"edition"`
	OverallStatus   string   `json:"overall_status"`
	Checks          []Check  `json:"checks"`
	Summary         Summary  `json:"summary"`
	Recommendations []string `json:"recommendations"`
}

// Summary represents the summary stats of compliance checks
type Summary struct {
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"non_compliant"`
	NotChecked   int `json:"not_checked"`
}

// OAuthCredentials for storing OAuth client credentials
type OAuthCredentials struct {
	Installed struct {
		ClientID                string   `json:"client_id"`
		ProjectID               string   `json:"project_id"`
		AuthURI                 string   `json:"auth_uri"`
		TokenURI                string   `json:"token_uri"`
		AuthProviderX509CertURL string   `json:"auth_provider_x509_cert_url"`
		ClientSecret            string   `json:"client_secret"`
		RedirectURIs            []string `json:"redirect_uris"`
	} `json:"installed"`
}

// ServiceAccountCredentials for storing service account credentials
type ServiceAccountCredentials struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// Global configuration
var DEFAULT_CONFIG = Config{
	CredentialsPath:  "./credentials.json",
	TokenPath:        "./token.json",
	ReportOutputPath: "./fedramp-compliance-report.json",
	AuthMethod:       "oauth",
	Scopes: []string{
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.domain.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
		"https://www.googleapis.com/auth/admin.reports.audit.readonly",
		"https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
		"https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly",
		"https://www.googleapis.com/auth/admin.directory.customer.readonly",
		"https://www.googleapis.com/auth/apps.licensing",
	},
}

// Environment variable names
const (
	ENV_VAR_CREDENTIALS_PATH  = "GOOGLE_APPLICATION_CREDENTIALS"
	ENV_VAR_TOKEN_PATH        = "GOOGLE_WORKSPACE_TOKEN_PATH"
	ENV_VAR_CONFIG_PATH       = "FEDRAMP_CONFIG_PATH"
	ENV_VAR_REPORT_PATH       = "FEDRAMP_REPORT_PATH"
	ENV_VAR_SERVICE_ACCOUNT   = "GOOGLE_SERVICE_ACCOUNT_JSON"
	ENV_VAR_ADMIN_EMAIL       = "GOOGLE_ADMIN_EMAIL"
	ENV_VAR_GCP_PROJECT       = "GCP_PROJECT_ID"
	ENV_VAR_GCP_SECRET_CREDS  = "GCP_SECRET_CREDENTIALS"
	ENV_VAR_AWS_SECRET_NAME   = "AWS_SECRET_NAME"
	ENV_VAR_AWS_REGION        = "AWS_REGION"
	ENV_VAR_VAULT_ADDR        = "VAULT_ADDR"
	ENV_VAR_VAULT_TOKEN       = "VAULT_TOKEN"
	ENV_VAR_VAULT_PATH        = "VAULT_SECRET_PATH"
	ENV_VAR_AUTH_METHOD       = "FEDRAMP_AUTH_METHOD"
)

// FedRAMP authorized services for Workspace
var FEDRAMP_AUTHORIZED_SERVICES = []string{
	"Gmail",
	"Calendar",
	"Drive and Docs",
	"Meet",
	"Chat",
	"Google Voice",
	"Classroom",
	"Keep",
	"Groups for Business",
	"Google Cloud Search",
	"Sites",
	"Vault",
	"Security Center",
}

// Define all FedRAMP compliance checks
var FEDRAMP_CHECKS = []Check{
	{
		ID:          "fedramp-authorized-services",
		Name:        "FedRAMP Authorized Services",
		Description: "Check if only FedRAMP authorized services are enabled for users within FedRAMP boundary",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "In Admin Console, navigate to Apps > Google Workspace > Services. Ensure only FedRAMP authorized services are enabled.",
	},
	{
		ID:          "data-region-policy",
		Name:        "Data Region Policy",
		Description: "Verify data region policy is set to United States for FedRAMP compliance",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "In Admin Console, go to Account > Settings > Data Regions and set the policy to United States.",
	},
	{
		ID:          "assured-controls",
		Name:        "Assured Controls",
		Description: "Check if Assured Controls add-on is enabled (Enterprise Plus only)",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Purchase and enable the Assured Controls add-on for your Google Workspace Enterprise Plus subscription.",
	},
	{
		ID:          "access-transparency",
		Name:        "Access Transparency",
		Description: "Verify that Access Transparency is enabled to monitor Google staff actions",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Go to Security > Access Transparency in Admin Console and enable this feature.",
	},
	{
		ID:          "password-policy",
		Name:        "Password Policy",
		Description: "Check if password policy meets FedRAMP requirements (minimum 12 chars, complexity, etc.)",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Navigate to Security > Password management in Admin Console and update settings to require minimum 12 characters, complexity, and 60-day expiration.",
	},
	{
		ID:          "two-step-verification",
		Name:        "Two-Step Verification",
		Description: "Verify 2-Step Verification is enforced for all users",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Go to Security > 2-Step Verification in Admin Console and enforce for all users.",
	},
	{
		ID:          "admin-privileges",
		Name:        "Admin Privileges",
		Description: "Check if admin privileges follow the principle of least privilege",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Review admin role assignments in Admin > Account > Admin roles and ensure only necessary privileges are assigned.",
	},
	{
		ID:          "audit-logging",
		Name:        "Audit Logging",
		Description: "Verify comprehensive audit logging is enabled for monitoring",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Configure audit logging in Admin > Security > Audit and investigation tools.",
	},
	{
		ID:          "security-center",
		Name:        "Security Center",
		Description: "Check if Security Center is configured (Enterprise Plus only)",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "If using Enterprise Plus, go to Security > Security Center and ensure it is properly configured.",
	},
	{
		ID:          "data-loss-prevention",
		Name:        "Data Loss Prevention",
		Description: "Check if DLP policies are configured to prevent data leakage",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Set up DLP policies in Security > Data protection to prevent accidental data leakage of sensitive information.",
	},
	{
		ID:          "context-aware-access",
		Name:        "Context-Aware Access",
		Description: "Verify context-aware access policies are in place to restrict access based on context (Enterprise Plus)",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Configure context-aware access in Security > Access and data control > Context-Aware Access.",
	},
	{
		ID:          "endpoint-management",
		Name:        "Endpoint Management",
		Description: "Check if endpoint management is configured for devices",
		Status:      "Not Checked",
		Details:     "",
		FixSteps:    "Set up endpoint management in Devices > Mobile & endpoints.",
	},
}

// parseFlags parses command line flags
func parseFlags() Config {
	config := DEFAULT_CONFIG

	// Define command line flags
	credentialsPath := flag.String("credentials", "", "Path to OAuth credentials JSON file")
	tokenPath := flag.String("token", "", "Path to OAuth token JSON file")
	reportPath := flag.String("report", "", "Path where compliance report will be saved")
	configFilePath := flag.String("config", "", "Path to configuration file (JSON)")
	serviceAccountPath := flag.String("service-account", "", "Path to service account JSON file")
	adminEmail := flag.String("admin-email", "", "Admin email (required for service account domain-wide delegation)")
	authMethod := flag.String("auth-method", "", "Authentication method (oauth, service_account, gcp_secret, aws_secret, vault, interactive)")
	gcpSecretName := flag.String("gcp-secret", "", "GCP Secret Manager path for credentials")
	awsSecretName := flag.String("aws-secret", "", "AWS Secrets Manager secret name")
	awsRegion := flag.String("aws-region", "", "AWS region for Secrets Manager")
	vaultPath := flag.String("vault-path", "", "HashiCorp Vault path for credentials")
	interactive := flag.Bool("interactive", false, "Interactive mode - prompt for credentials")

	flag.Parse()

	// First check for config file
	if *configFilePath != "" {
		loadedConfig, err := loadConfigFromFile(*configFilePath)
		if err == nil {
			config = loadedConfig
		} else {
			log.Printf("Error loading config file: %v", err)
		}
	}

	// Environment variables override config file
	if envPath := os.Getenv(ENV_VAR_CREDENTIALS_PATH); envPath != "" {
		config.CredentialsPath = envPath
	}
	if envPath := os.Getenv(ENV_VAR_TOKEN_PATH); envPath != "" {
		config.TokenPath = envPath
	}
	if envPath := os.Getenv(ENV_VAR_REPORT_PATH); envPath != "" {
		config.ReportOutputPath = envPath
	}
	if envAdminEmail := os.Getenv(ENV_VAR_ADMIN_EMAIL); envAdminEmail != "" {
		config.AdminEmail = envAdminEmail
	}
	if envAuthMethod := os.Getenv(ENV_VAR_AUTH_METHOD); envAuthMethod != "" {
		config.AuthMethod = envAuthMethod
	}

	// Command line flags override environment variables
	if *credentialsPath != "" {
		config.CredentialsPath = *credentialsPath
	}
	if *tokenPath != "" {
		config.TokenPath = *tokenPath
	}
	if *reportPath != "" {
		config.ReportOutputPath = *reportPath
	}
	if *adminEmail != "" {
		config.AdminEmail = *adminEmail
	}

	// Auth method selection (flags take priority)
	if *authMethod != "" {
		config.AuthMethod = *authMethod
	} else if *interactive {
		config.AuthMethod = "interactive"
	} else if *serviceAccountPath != "" {
		config.AuthMethod = "service_account"
		config.ServiceAccountPath = *serviceAccountPath
	} else if *gcpSecretName != "" {
		config.AuthMethod = "gcp_secret"
		config.GCPSecretName = *gcpSecretName
	} else if *awsSecretName != "" {
		config.AuthMethod = "aws_secret"
		config.AWSSecretName = *awsSecretName
		if *awsRegion != "" {
			config.AWSRegion = *awsRegion
		}
	} else if *vaultPath != "" {
		config.AuthMethod = "vault"
		config.VaultPath = *vaultPath
	} else if sa := os.Getenv(ENV_VAR_SERVICE_ACCOUNT); sa != "" {
		config.AuthMethod = "service_account"
		// Service account JSON directly in environment variable
		// Handled during auth flow
	} else if gcpSecret := os.Getenv(ENV_VAR_GCP_SECRET_CREDS); gcpSecret != "" {
		config.AuthMethod = "gcp_secret"
		config.GCPSecretName = gcpSecret
	} else if awsSecret := os.Getenv(ENV_VAR_AWS_SECRET_NAME); awsSecret != "" {
		config.AuthMethod = "aws_secret"
		config.AWSSecretName = awsSecret
		if region := os.Getenv(ENV_VAR_AWS_REGION); region != "" {
			config.AWSRegion = region
		}
	} else if vaultPath := os.Getenv(ENV_VAR_VAULT_PATH); vaultPath != "" {
		config.AuthMethod = "vault"
		config.VaultPath = vaultPath
		if vaultAddr := os.Getenv(ENV_VAR_VAULT_ADDR); vaultAddr != "" {
			config.VaultAddress = vaultAddr
		}
		if vaultToken := os.Getenv(ENV_VAR_VAULT_TOKEN); vaultToken != "" {
			config.VaultToken = vaultToken
		}
	}

	return config
}

// loadConfigFromFile loads config from JSON file
func loadConfigFromFile(path string) (Config, error) {
	var config Config

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	// Fill in any missing fields with defaults
	if config.CredentialsPath == "" {
		config.CredentialsPath = DEFAULT_CONFIG.CredentialsPath
	}
	if config.TokenPath == "" {
		config.TokenPath = DEFAULT_CONFIG.TokenPath
	}
	if config.ReportOutputPath == "" {
		config.ReportOutputPath = DEFAULT_CONFIG.ReportOutputPath
	}
	if len(config.Scopes) == 0 {
		config.Scopes = DEFAULT_CONFIG.Scopes
	}
	if config.AuthMethod == "" {
		config.AuthMethod = DEFAULT_CONFIG.AuthMethod
	}

	return config, nil
}

// getClient retrieves a client from auth token or user login
func getClient(ctx context.Context, config *oauth2.Config, tokenPath string) (*http.Client, error) {
	tok, err := tokenFromFile(tokenPath)
	if err != nil {
		tok, err = getTokenFromWeb(ctx, config)
		if err != nil {
			return nil, err
		}
		saveToken(tokenPath, tok)
	}
	return config.Client(ctx, tok), nil
}

// getTokenFromWeb uses config to request a token
func getTokenFromWeb(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	// Generate a random state string for CSRF protection
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	state := base64.StdEncoding.EncodeToString(b)

	// Create a temporary web server to handle the OAuth callback
	ch := make(chan *oauth2.Token)
	errCh := make(chan error, 1)

	// Create a server to listen for the callback
	// Get a free port
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		if queryParams.Get("state") != state {
			errCh <- fmt.Errorf("invalid state parameter")
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		code := queryParams.Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code provided")
			http.Error(w, "No code provided", http.StatusBadRequest)
			return
		}

		token, err := config.Exchange(ctx, code)
		if err != nil {
			errCh <- fmt.Errorf("unable to exchange code for token: %v", err)
			http.Error(w, fmt.Sprintf("Unable to exchange code for token: %v", err), http.StatusInternalServerError)
			return
		}

		// Send token to the main goroutine
		ch <- token

		// Send success response to browser
		fmt.Fprintf(w, "Authentication successful! You can close this window.")
	})

	server := &http.Server{
		Addr:    "localhost:0", // Let the OS choose a free port
		Handler: handler,
	}

	// Find out which port was assigned
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, fmt.Errorf("unable to start listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	// Update redirect URI to use the selected port
	config.RedirectURL = fmt.Sprintf("http://localhost:%d", port)

	// Start the server in a goroutine
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %v", err)
		}
	}()
	defer server.Close()

	// Generate the authorization URL
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser: \n%v\n", authURL)

	// Wait for the token or error
	select {
	case token := <-ch:
		return token, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// tokenFromFile retrieves a token from a file
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// saveToken saves a token to a file
func saveToken(path string, token *oauth2.Token) error {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache oauth token: %v", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

// getAuthFromOAuth handles OAuth-based authentication
func getAuthFromOAuth(ctx context.Context, config Config) (*http.Client, error) {
	b, err := ioutil.ReadFile(config.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read client secret file: %v", err)
	}

	oauthConfig, err := google.ConfigFromJSON(b, config.Scopes...)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret file to config: %v", err)
	}

	return getClient(ctx, oauthConfig, config.TokenPath)
}

// getAuthFromServiceAccount handles service account authentication
func getAuthFromServiceAccount(ctx context.Context, config Config) (*http.Client, error) {
	var b []byte
	var err error

	// Check if service account JSON is in an environment variable
	if saEnv := os.Getenv(ENV_VAR_SERVICE_ACCOUNT); saEnv != "" {
		b = []byte(saEnv)
	} else if config.ServiceAccountPath != "" {
		// Read from file
		b, err = ioutil.ReadFile(config.ServiceAccountPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read service account file: %v", err)
		}
	} else {
		return nil, fmt.Errorf("no service account information provided")
	}

	// Get admin email for domain-wide delegation
	adminEmail := config.AdminEmail
	if adminEmail == "" {
		adminEmail = os.Getenv(ENV_VAR_ADMIN_EMAIL)
		if adminEmail == "" {
			return nil, fmt.Errorf("admin email is required for service account domain-wide delegation")
		}
	}

	// Parse as JWT config
	jwtConfig, err := google.JWTConfigFromJSON(b, config.Scopes...)
	if err != nil {
		return nil, fmt.Errorf("unable to parse service account file to JWT config: %v", err)
	}

	// Set the subject (admin email) for domain-wide delegation
	jwtConfig.Subject = adminEmail

	// Create the HTTP client
	return jwtConfig.Client(ctx), nil
}

// getSecretFromGCP retrieves a secret from Google Cloud Secret Manager
func getSecretFromGCP(ctx context.Context, projectID, secretName string) (string, error) {
	// For simplicity, we use the REST API directly instead of the client library
	// In a production environment, you'd want to use the client library
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/latest:access",
		projectID, secretName), nil)
	if err != nil {
		return "", err
	}

	// Use Application Default Credentials (ADC) for authentication
	tokenSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return "", fmt.Errorf("unable to get token source: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("unable to get token: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("error getting secret: %s, status: %d", string(body), resp.StatusCode)
	}

	var result struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding response: %v", err)
	}

	secretData, err := base64.StdEncoding.DecodeString(result.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("error decoding secret data: %v", err)
	}

	return string(secretData), nil
}

// getSecretFromAWS retrieves a secret from AWS Secrets Manager
func getSecretFromAWS(secretName, region string) (string, error) {
	// For simplicity, we simulate getting a secret from AWS
	// In a real environment, you'd use the AWS SDK
	// This is a placeholder implementation
	return "", fmt.Errorf("AWS Secrets Manager integration not implemented")
}

// getSecretFromVault retrieves a secret from HashiCorp Vault
func getSecretFromVault(vaultAddr, vaultToken, path string) (map[string]interface{}, error) {
	// For simplicity, we simulate getting a secret from Vault
	// In a real environment, you'd use the Vault API
	// This is a placeholder implementation
	return nil, fmt.Errorf("HashiCorp Vault integration not implemented")
}

// getAuthFromInteractive prompts user for credentials
func getAuthFromInteractive(ctx context.Context, config Config) (*http.Client, error) {
	fmt.Println("Interactive Authentication Mode")
	fmt.Println("==============================")

	fmt.Print("Select authentication type (oauth, service_account): ")
	reader := bufio.NewReader(os.Stdin)
	authTypeStr, _ := reader.ReadString('\n')
	authType := strings.TrimSpace(authTypeStr)

	if authType == "oauth" {
		fmt.Print("Enter OAuth Client ID: ")
		clientID, _ := reader.ReadString('\n')
		clientID = strings.TrimSpace(clientID)

		fmt.Print("Enter OAuth Client Secret: ")
		clientSecret, _ := reader.ReadString('\n')
		clientSecret = strings.TrimSpace(clientSecret)

		// Create OAuth config
		oauthConfig := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       config.Scopes,
			RedirectURL:  "http://localhost",
		}

		return getClient(ctx, oauthConfig, "")
	} else if authType == "service_account" {
		fmt.Println("Enter service account JSON (paste entire content, then press Enter twice):")
		var jsonStr string
		for {
			line, _ := reader.ReadString('\n')
			if line == "\n" || line == "\r\n" {
				break
			}
			jsonStr += line
		}

		fmt.Print("Enter admin email for domain-wide delegation: ")
		adminEmail, _ := reader.ReadString('\n')
		adminEmail = strings.TrimSpace(adminEmail)

		// Parse as JWT config
		jwtConfig, err := google.JWTConfigFromJSON([]byte(jsonStr), config.Scopes...)
		if err != nil {
			return nil, fmt.Errorf("unable to parse service account JSON: %v", err)
		}

		// Set the subject (admin email) for domain-wide delegation
		jwtConfig.Subject = adminEmail

		// Create the HTTP client
		return jwtConfig.Client(ctx), nil
	}

	return nil, fmt.Errorf("unknown authentication type: %s", authType)
}

// getAuth authenticates with Google API using the configured method
func getAuth(ctx context.Context, config Config) (*http.Client, error) {
	fmt.Printf("Using authentication method: %s\n", config.AuthMethod)

	switch config.AuthMethod {
	case "oauth":
		return getAuthFromOAuth(ctx, config)
	case "service_account":
		return getAuthFromServiceAccount(ctx, config)
	case "interactive":
		return getAuthFromInteractive(ctx, config)
	case "gcp_secret":
		// Get credentials from GCP Secret Manager
		projectID := config.GCPSecretProject
		if projectID == "" {
			projectID = os.Getenv(ENV_VAR_GCP_PROJECT)
			if projectID == "" {
				return nil, fmt.Errorf("GCP project ID not provided")
			}
		}

		secretName := config.GCPSecretName
		if secretName == "" {
			secretName = os.Getenv(ENV_VAR_GCP_SECRET_CREDS)
			if secretName == "" {
				return nil, fmt.Errorf("GCP secret name not provided")
			}
		}

		secretData, err := getSecretFromGCP(ctx, projectID, secretName)
		if err != nil {
			return nil, fmt.Errorf("error fetching secret from GCP: %v", err)
		}

		// Determine if it's service account or OAuth credentials
		var credMap map[string]interface{}
		if err := json.Unmarshal([]byte(secretData), &credMap); err != nil {
			return nil, fmt.Errorf("error parsing secret data: %v", err)
		}

		if credType, ok := credMap["type"]; ok && credType == "service_account" {
			// It's a service account
			adminEmail := config.AdminEmail
			if adminEmail == "" {
				adminEmail = os.Getenv(ENV_VAR_ADMIN_EMAIL)
				if adminEmail == "" {
					return nil, fmt.Errorf("admin email is required for service account domain-wide delegation")
				}
			}

			jwtConfig, err := google.JWTConfigFromJSON([]byte(secretData), config.Scopes...)
			if err != nil {
				return nil, fmt.Errorf("unable to parse service account JSON from secret: %v", err)
			}

			jwtConfig.Subject = adminEmail
			return jwtConfig.Client(ctx), nil
		} else {
			// Assume it's OAuth credentials
			oauthConfig, err := google.ConfigFromJSON([]byte(secretData), config.Scopes...)
			if err != nil {
				return nil, fmt.Errorf("unable to parse OAuth credentials from secret: %v", err)
			}

			return getClient(ctx, oauthConfig, config.TokenPath)
		}

	case "aws_secret":
		// Get credentials from AWS Secrets Manager
		secretName := config.AWSSecretName
		if secretName == "" {
			secretName = os.Getenv(ENV_VAR_AWS_SECRET_NAME)
			if secretName == "" {
				return nil, fmt.Errorf("AWS secret name not provided")
			}
		}

		region := config.AWSRegion
		if region == "" {
			region = os.Getenv(ENV_VAR_AWS_REGION)
			if region == "" {
				region = "us-east-1" // Default region
			}
		}

		secretData, err := getSecretFromAWS(secretName, region)
		if err != nil {
			return nil, fmt.Errorf("error fetching secret from AWS: %v", err)
		}

		// Logic similar to GCP secret handler
		var credMap map[string]interface{}
		if err := json.Unmarshal([]byte(secretData), &credMap); err != nil {
			return nil, fmt.Errorf("error parsing secret data: %v", err)
		}

		if credType, ok := credMap["type"]; ok && credType == "service_account" {
			// It's a service account
			adminEmail := config.AdminEmail
			if adminEmail == "" {
				adminEmail = os.Getenv(ENV_VAR_ADMIN_EMAIL)
				if adminEmail == "" {
					return nil, fmt.Errorf("admin email is required for service account domain-wide delegation")
				}
			}

			jwtConfig, err := google.JWTConfigFromJSON([]byte(secretData), config.Scopes...)
			if err != nil {
				return nil, fmt.Errorf("unable to parse service account JSON from secret: %v", err)
			}

			jwtConfig.Subject = adminEmail
			return jwtConfig.Client(ctx), nil
		} else {
			// Assume it's OAuth credentials
			oauthConfig, err := google.ConfigFromJSON([]byte(secretData), config.Scopes...)
			if err != nil {
				return nil, fmt.Errorf("unable to parse OAuth credentials from secret: %v", err)
			}

			return getClient(ctx, oauthConfig, config.TokenPath)
		}

	case "vault":
		// Get credentials from HashiCorp Vault
		vaultAddr := config.VaultAddress
		if vaultAddr == "" {
			vaultAddr = os.Getenv(ENV_VAR_VAULT_ADDR)
			if vaultAddr == "" {
				return nil, fmt.Errorf("Vault address not provided")
			}
		}

		vaultToken := config.VaultToken
		if vaultToken == "" {
			vaultToken = os.Getenv(ENV_VAR_VAULT_TOKEN)
			if vaultToken == "" {
				return nil, fmt.Errorf("Vault token not provided")
			}
		}

		vaultPath := config.VaultPath
		if vaultPath == "" {
			vaultPath = os.Getenv(ENV_VAR_VAULT_PATH)
			if vaultPath == "" {
				return nil, fmt.Errorf("Vault path not provided")
			}
		}

		secretData, err := getSecretFromVault(vaultAddr, vaultToken, vaultPath)
		if err != nil {
			return nil, fmt.Errorf("error fetching secret from Vault: %v", err)
		}

		// Logic to handle different secret formats from Vault
		// For brevity, this is a placeholder
		return nil, fmt.Errorf("Vault integration not fully implemented")

	default:
		return nil, fmt.Errorf("unknown authentication method: %s", config.AuthMethod)
	}
}

// findCheckIndex finds the index of a check by ID
func findCheckIndex(checks []Check, id string) int {
	for i, check := range checks {
		if check.ID == id {
			return i
		}
	}
	return -1
}

// checkAuthorizedServices checks if only FedRAMP authorized services are enabled
func checkAuthorizedServices(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking FedRAMP Authorized Services...")
	
	checkIndex := findCheckIndex(report.Checks, "fedramp-authorized-services")
	if checkIndex == -1 {
		log.Println("Check 'fedramp-authorized-services' not found")
		return
	}
	
	// This would require the Service Management API
	// In a real implementation, you'd fetch all enabled services and compare against the authorized list
	
	// Since direct API for this is not available for Workspace, we provide manual validation guidance
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Please check Admin Console > Apps > Google Workspace > " +
		"Services and ensure only FedRAMP authorized services are enabled for users in FedRAMP boundary.\n\n" +
		"FedRAMP authorized services for Google Workspace include: " + strings.Join(FEDRAMP_AUTHORIZED_SERVICES, ", ")
	
	// Don't update summary as this requires manual verification
}

// checkDataRegionPolicy checks data region policy setting
func checkDataRegionPolicy(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Data Region Policy...")
	
	checkIndex := findCheckIndex(report.Checks, "data-region-policy")
	if checkIndex == -1 {
		log.Println("Check 'data-region-policy' not found")
		return
	}
	
	// Currently, there is no direct API to check data region policy settings
	// This would require manual verification in the Admin Console
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. For FedRAMP compliance, data region should be set to United States. " +
		"Check in Admin Console > Account > Settings > Data Regions."
	
	// Don't update summary as this requires manual verification
}

// checkAssuredControls checks for Assured Controls add-on
func checkAssuredControls(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Assured Controls...")
	
	checkIndex := findCheckIndex(report.Checks, "assured-controls")
	if checkIndex == -1 {
		log.Println("Check 'assured-controls' not found")
		return
	}
	
	// This would require checking licensing information through the Licensing API
	// Unfortunately, direct API access to check for this add-on is limited
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Assured Controls is an add-on for Enterprise Plus edition " +
		"that allows precise control over cloud service provider access."
	
	// Don't update summary as this requires manual verification
}

// checkAccessTransparency checks Access Transparency setting
func checkAccessTransparency(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Access Transparency...")
	
	checkIndex := findCheckIndex(report.Checks, "access-transparency")
	if checkIndex == -1 {
		log.Println("Check 'access-transparency' not found")
		return
	}
	
	// API for checking if Access Transparency is enabled is not directly available
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Access Transparency provides logs of actions taken by Google staff. " +
		"Verify this is enabled in Admin Console > Security > Access Transparency."
	
	// Don't update summary as this requires manual verification
}

// checkPasswordPolicy checks password policy settings
func checkPasswordPolicy(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Password Policy...")
	
	checkIndex := findCheckIndex(report.Checks, "password-policy")
	if checkIndex == -1 {
		log.Println("Check 'password-policy' not found")
		return
	}
	
	ctx := context.Background()
	directoryService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Printf("Error creating directory service: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	// Get password policy settings
	customer, err := directoryService.Customers.Get("my_customer").Do()
	if err != nil {
		log.Printf("Error getting customer: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	if customer != nil && customer.PasswordStatus != nil {
		isCompliant := true
		var details []string
		
		// Check minimum length (FedRAMP requires at least 12 characters)
		if customer.PasswordStatus.PasswordMinimumLength == nil || *customer.PasswordStatus.PasswordMinimumLength < 12 {
			isCompliant = false
			minLength := "not set"
			if customer.PasswordStatus.PasswordMinimumLength != nil {
				minLength = fmt.Sprintf("%d", *customer.PasswordStatus.PasswordMinimumLength)
			}
			details = append(details, fmt.Sprintf("Password minimum length is %s, should be at least 12 characters", minLength))
		}
		
		// Check complexity requirements
		if customer.PasswordStatus.EnforcePasswordPolicy == nil || !*customer.PasswordStatus.EnforcePasswordPolicy {
			isCompliant = false
			details = append(details, "Password policy enforcement is not enabled")
		}
		
		// Check password expiration (FedRAMP requires maximum 60 days)
		if customer.PasswordStatus.PasswordMaximumLength == nil || *customer.PasswordStatus.PasswordMaximumLength > 60 {
			isCompliant = false
			maxLength := "not set"
			if customer.PasswordStatus.PasswordMaximumLength != nil {
				maxLength = fmt.Sprintf("%d", *customer.PasswordStatus.PasswordMaximumLength)
			}
			details = append(details, fmt.Sprintf("Password expiration is %s days, should be 60 days or less", maxLength))
		}
		
		if isCompliant {
			report.Checks[checkIndex].Status = "Compliant"
			report.Checks[checkIndex].Details = "Password policy meets FedRAMP requirements"
			report.Summary.Compliant++
		} else {
			report.Checks[checkIndex].Status = "Not Compliant"
			report.Checks[checkIndex].Details = fmt.Sprintf("Password policy does not meet FedRAMP requirements: %s", strings.Join(details, "; "))
			report.Summary.NonCompliant++
		}
		
		report.Summary.NotChecked--
	} else {
		report.Checks[checkIndex].Status = "Not Checked"
		report.Checks[checkIndex].Details = "Could not retrieve password policy settings"
	}
}

// checkTwoStepVerification checks if 2-Step Verification is enforced
func checkTwoStepVerification(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Two-Step Verification...")
	
	checkIndex := findCheckIndex(report.Checks, "two-step-verification")
	if checkIndex == -1 {
		log.Println("Check 'two-step-verification' not found")
		return
	}
	
	ctx := context.Background()
	directoryService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Printf("Error creating directory service: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	// Get 2SV settings
	customer, err := directoryService.Customers.Get("my_customer").Do()
	if err != nil {
		log.Printf("Error getting customer: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	if customer != nil && customer.IsEnforcedIn2Sv != nil && *customer.IsEnforcedIn2Sv {
		report.Checks[checkIndex].Status = "Compliant"
		report.Checks[checkIndex].Details = "2-Step Verification is enforced domain-wide"
		report.Summary.Compliant++
		report.Summary.NotChecked--
	} else {
		report.Checks[checkIndex].Status = "Not Compliant"
		report.Checks[checkIndex].Details = "2-Step Verification is not enforced domain-wide"
		report.Summary.NonCompliant++
		report.Summary.NotChecked--
	}
}

// checkAdminPrivileges checks admin privileges for principle of least privilege
func checkAdminPrivileges(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Admin Privileges...")
	
	checkIndex := findCheckIndex(report.Checks, "admin-privileges")
	if checkIndex == -1 {
		log.Println("Check 'admin-privileges' not found")
		return
	}
	
	ctx := context.Background()
	directoryService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Printf("Error creating directory service: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	// Get role assignments
	roleAssignments, err := directoryService.RoleAssignments.List("my_customer").Do()
	if err != nil {
		log.Printf("Error getting role assignments: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	if roleAssignments != nil && len(roleAssignments.Items) > 0 {
		// Count super admin assignments (role ID 101)
		superAdminCount := 0
		for _, role := range roleAssignments.Items {
			if role.RoleId == "101" {
				superAdminCount++
			}
		}
		
		// Get total admin count
		adminCount := len(roleAssignments.Items)
		
		// For FedRAMP, principle of least privilege means minimizing super admin accounts
		// Using a threshold of 3 super admins as a reasonable assumption
		isCompliant := superAdminCount <= 3
		
		if isCompliant {
			report.Checks[checkIndex].Status = "Compliant"
			report.Checks[checkIndex].Details = fmt.Sprintf("Admin role assignments follow principle of least privilege. Total admin accounts: %d, Super admin accounts: %d", adminCount, superAdminCount)
			report.Summary.Compliant++
		} else {
			report.Checks[checkIndex].Status = "Not Compliant"
			report.Checks[checkIndex].Details = fmt.Sprintf("Too many super admin accounts (%d). For principle of least privilege, limit super admin accounts to 3 or fewer. Total admin accounts: %d", superAdminCount, adminCount)
			report.Summary.NonCompliant++
		}
		
		report.Summary.NotChecked--
	} else {
		report.Checks[checkIndex].Status = "Not Checked"
		report.Checks[checkIndex].Details = "Could not retrieve admin role assignments"
	}
}

// checkAuditLogging checks audit logging configuration
func checkAuditLogging(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Audit Logging...")
	
	checkIndex := findCheckIndex(report.Checks, "audit-logging")
	if checkIndex == -1 {
		log.Println("Check 'audit-logging' not found")
		return
	}
	
	ctx := context.Background()
	reportsService, err := reports.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Printf("Error creating reports service: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	// Try to fetch admin audit logs to check if audit logging is enabled
	activities, err := reportsService.Activities.List("all", "admin").MaxResults(1).Do()
	if err != nil {
		log.Printf("Error getting audit logs: %v", err)
		report.Checks[checkIndex].Status = "Error"
		report.Checks[checkIndex].Details = fmt.Sprintf("Error during check: %v", err)
		return
	}
	
	isLoggingEnabled := activities != nil && len(activities.Items) > 0
	
	if isLoggingEnabled {
		report.Checks[checkIndex].Status = "Compliant"
		report.Checks[checkIndex].Details = "Audit logging is enabled and capturing events"
		report.Summary.Compliant++
	} else {
		report.Checks[checkIndex].Status = "Not Compliant"
		report.Checks[checkIndex].Details = "Audit logging does not appear to be capturing events"
		report.Summary.NonCompliant++
	}
	
	report.Summary.NotChecked--
}

// checkSecurityCenter checks Security Center configuration
func checkSecurityCenter(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Security Center...")
	
	checkIndex := findCheckIndex(report.Checks, "security-center")
	if checkIndex == -1 {
		log.Println("Check 'security-center' not found")
		return
	}
	
	// API for checking Security Center configuration is not available
	// This requires Enterprise Plus and manual verification
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Security Center is available for Enterprise Plus users. " +
		"Check Admin Console > Security > Security Center."
	
	// Don't update summary as this requires manual verification
}

// checkDLP checks Data Loss Prevention policies
func checkDLP(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Data Loss Prevention...")
	
	checkIndex := findCheckIndex(report.Checks, "data-loss-prevention")
	if checkIndex == -1 {
		log.Println("Check 'data-loss-prevention' not found")
		return
	}
	
	// API for checking DLP configuration is not available
	// This requires manual verification
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Check Admin Console > Security > Data protection " +
		"to verify if DLP rules are configured."
	
	// Don't update summary as this requires manual verification
}

// checkContextAwareAccess checks Context-Aware Access policies
func checkContextAwareAccess(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Context-Aware Access...")
	
	checkIndex := findCheckIndex(report.Checks, "context-aware-access")
	if checkIndex == -1 {
		log.Println("Check 'context-aware-access' not found")
		return
	}
	
	// API for checking Context-Aware Access is not available
	// This requires Enterprise Plus and manual verification
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Context-Aware Access is available for Enterprise Plus users. " +
		"Check Admin Console > Security > Access and data control > Context-Aware Access."
	
	// Don't update summary as this requires manual verification
}

// checkEndpointManagement checks endpoint management configuration
func checkEndpointManagement(client *http.Client, report *ComplianceReport) {
	fmt.Println("Checking Endpoint Management...")
	
	checkIndex := findCheckIndex(report.Checks, "endpoint-management")
	if checkIndex == -1 {
		log.Println("Check 'endpoint-management' not found")
		return
	}
	
	// API for checking endpoint management is not available
	// This requires manual verification
	
	report.Checks[checkIndex].Status = "Not Checked"
	report.Checks[checkIndex].Details = "Manual verification required. Check Admin Console > Devices > Mobile & endpoints " +
		"to verify endpoint management settings."
	
	// Don't update summary as this requires manual verification
}

// generateRecommendations generates recommendations based on non-compliant checks
func generateRecommendations(report *ComplianceReport) {
	for _, check := range report.Checks {
		if check.Status == "Not Compliant" {
			report.Recommendations = append(report.Recommendations, fmt.Sprintf("%s: %s", check.Name, check.FixSteps))
		}
	}
}

// checkFedRAMPCompliance is the main function to execute all compliance checks
func checkFedRAMPCompliance() {
	// Parse command line flags and load config
	config := parseFlags()

	complianceReport := ComplianceReport{
		Timestamp:     time.Now().Format(time.RFC3339),
		DomainName:    "",
		Edition:       "",
		OverallStatus: "Not Compliant",
		Checks:        FEDRAMP_CHECKS,
		Summary: Summary{
			Compliant:    0,
			NonCompliant: 0,
			NotChecked:   len(FEDRAMP_CHECKS),
		},
		Recommendations: []string{},
	}

	ctx := context.Background()

	// Authenticate
	client, err := getAuth(ctx, config)
	if err != nil {
		log.Fatalf("Error authenticating: %v", err)
	}
	fmt.Println("✓ Authentication successful")

	directoryService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Error creating directory service: %v", err)
	}

	// Get domain information
	domains, err := directoryService.Domains.List("my_customer").Do()
	if err != nil {
		log.Printf("Error retrieving domain information: %v", err)
	} else if domains != nil && len(domains.Domains) > 0 {
		complianceReport.DomainName = domains.Domains[0].DomainName
		fmt.Printf("✓ Retrieved domain: %s\n", complianceReport.DomainName)
	}

	// Get customer information (to determine edition)
	customer, err := directoryService.Customers.Get("my_customer").Do()
	if err != nil {
		log.Printf("Error retrieving customer information: %v", err)
	} else if customer != nil {
		complianceReport.Edition = customer.CustomerDomain
		fmt.Println("✓ Retrieved customer information")
	}

	// Run compliance checks
	checkAuthorizedServices(client, &complianceReport)
	checkDataRegionPolicy(client, &complianceReport)
	checkAssuredControls(client, &complianceReport)
	checkAccessTransparency(client, &complianceReport)
	checkPasswordPolicy(client, &complianceReport)
	checkTwoStepVerification(client, &complianceReport)
	checkAdminPrivileges(client, &complianceReport)
	checkAuditLogging(client, &complianceReport)
	checkSecurityCenter(client, &complianceReport)
	checkDLP(client, &complianceReport)
	checkContextAwareAccess(client, &complianceReport)
	checkEndpointManagement(client, &complianceReport)

	// Generate recommendations for non-compliant checks
	generateRecommendations(&complianceReport)

	// Determine overall status
	if complianceReport.Summary.NonCompliant == 0 && complianceReport.Summary.NotChecked == 0 {
		complianceReport.OverallStatus = "Compliant"
	} else if complianceReport.Summary.NonCompliant > 0 {
		complianceReport.OverallStatus = "Not Compliant"
	} else {
		complianceReport.OverallStatus = "Partially Checked"
	}

	// Save report
	reportJSON, err := json.MarshalIndent(complianceReport, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling report: %v", err)
	}
	
	if err := ioutil.WriteFile(config.ReportOutputPath, reportJSON, 0644); err != nil {
		log.Fatalf("Error writing report: %v", err)
	}
	
	// Display summary
	fmt.Println("\n=== FedRAMP Compliance Report Summary ===")
	fmt.Printf("Domain: %s\n", complianceReport.DomainName)
	fmt.Printf("Edition: %s\n", complianceReport.Edition)
	fmt.Printf("Overall Status: %s\n", complianceReport.OverallStatus)
	fmt.Printf("Compliant Checks: %d\n", complianceReport.Summary.Compliant)
	fmt.Printf("Non-Compliant Checks: %d\n", complianceReport.Summary.NonCompliant)
	fmt.Printf("Checks Not Performed: %d\n", complianceReport.Summary.NotChecked)
	fmt.Printf("Report saved to: %s\n", config.ReportOutputPath)

	if len(complianceReport.Recommendations) > 0 {
		fmt.Println("\n=== Key Recommendations ===")
		for i, rec := range complianceReport.Recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
	}
}

func main() {
	checkFedRAMPCompliance()
}