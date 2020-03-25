package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

var (
	// Command line flags
	flagVersion            = flag.Bool("version", false, "Show the version number and information")
	flagManagedIdentityURL = flag.String("managed-identity-url", envString("MANAGED_IDENTITY_URL", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"), "token URL to request")
	flagBearerToken        = flag.String("bearer-token", envString("BEARER_TOKEN", ""), "bearer token to use. overrides managed identity url")
	flagAzureKeyVaultURL   = flag.String("keyvault-url", "", "secret URL to request")
	optionFlags            map[string]*string
	version                = "0.1.0"
)

func printUsage() {
	flag.Usage()
	os.Exit(1)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

func getAzureManagedIdentity() (string, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpReq, err := http.NewRequest("GET", *flagManagedIdentityURL, nil)

	if err != nil {
		return "", fmt.Errorf("error create managed identity request: %v", err)
	}

	httpReq.Header.Set("Metadata", "true")

	resp, err := netClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("error access managed identity url: %v", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("non 200 status code: %v", resp.StatusCode)
	}
	authData, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("error read managed identity response: %v", err)
	}

	var r tokenResponse
	err = json.Unmarshal(authData, &r)
	if err != nil {
		return "", fmt.Errorf("Error calling json.Unmarshal on the managed identity response: %v", err)
	}

	return r.AccessToken, nil
}

type secretResponse struct {
	Value string `json:"value"`
}

func getKeyVaultSecret() (string, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var managedIdentity string

	if *flagBearerToken != "" {
		managedIdentity = *flagBearerToken
	} else {
		var err error
		managedIdentity, err = getAzureManagedIdentity()
		if err != nil {
			return "", fmt.Errorf("error getting managed identity: %v", err)
		}
	}

	httpReq, err := http.NewRequest("GET", *flagAzureKeyVaultURL, nil)
	if err != nil {
		return "", fmt.Errorf("error create get key vault url request: %v", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+managedIdentity)

	resp, err := netClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("error get key vault url: %v", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("keyvault non 200 status code: %v", resp.StatusCode)
	}
	authData, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("error read keyvault response: %v", err)
	}

	var r secretResponse
	err = json.Unmarshal(authData, &r)
	if err != nil {
		return "", fmt.Errorf("Error calling json.Unmarshal on the keyvault response: %v", err)
	}

	return r.Value, nil
}

func main() {

	flag.Parse()
	if *flagVersion {
		fmt.Fprintf(os.Stderr, "Version: %v\n", version)
		os.Exit(0)
	}

	if *flagAzureKeyVaultURL == "" {
		fmt.Fprintf(os.Stderr, "Flag: missing key vault url\n")
		printUsage()
	}

	secret, err := getKeyVaultSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting secret: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s", secret)
}
