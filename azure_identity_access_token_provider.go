package microsoft_kiota_authentication_azure

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	u "net/url"

	azcore "github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	absauth "github.com/microsoft/kiota-abstractions-go/authentication"
)

// AzureIdentityAccessTokenProvider implementation of AccessTokenProvider that supports implementations of TokenCredential from Azure.Identity.
type AzureIdentityAccessTokenProvider struct {
	scopes                []string
	credential            azcore.TokenCredential
	allowedHostsValidator *absauth.AllowedHostsValidator
}

// NewAzureIdentityAccessTokenProvider creates a new instance of the AzureIdentityAccessTokenProvider using "https://graph.microsoft.com/.default" as the default scope.
func NewAzureIdentityAccessTokenProvider(credential azcore.TokenCredential) (*AzureIdentityAccessTokenProvider, error) {
	return NewAzureIdentityAccessTokenProviderWithScopes(credential, nil)
}

// NewAzureIdentityAccessTokenProviderWithScopes creates a new instance of the AzureIdentityAccessTokenProvider.
func NewAzureIdentityAccessTokenProviderWithScopes(credential azcore.TokenCredential, scopes []string) (*AzureIdentityAccessTokenProvider, error) {
	return NewAzureIdentityAccessTokenProviderWithScopesAndValidHosts(credential, scopes, nil)
}

// NewAzureIdentityAccessTokenProviderWithScopesAndValidhosts creates a new instance of the AzureIdentityAccessTokenProvider.
func NewAzureIdentityAccessTokenProviderWithScopesAndValidHosts(credential azcore.TokenCredential, scopes []string, validhosts []string) (*AzureIdentityAccessTokenProvider, error) {
	if credential == nil {
		return nil, errors.New("credential cannot be nil")
	}
	scopesLen := len(scopes)
	finalScopes := make([]string, scopesLen)
	if scopesLen == 0 {
		finalScopes = append(finalScopes, "https://graph.microsoft.com/.default")
	} else {
		copy(finalScopes, scopes)
	}
	validator := absauth.NewAllowedHostsValidator(validhosts)
	if len(validhosts) == 0 {
		validator = absauth.NewAllowedHostsValidator([]string{"graph.microsoft.com", "graph.microsoft.us", "dod-graph.microsoft.us", "graph.microsoft.de", "microsoftgraph.chinacloudapi.cn", "canary.graph.microsoft.com"})
	}
	result := &AzureIdentityAccessTokenProvider{
		credential:            credential,
		scopes:                finalScopes,
		allowedHostsValidator: &validator,
	}

	return result, nil
}

const claimsKey = "claims"

// GetAuthorizationToken returns the access token for the provided url.
func (p *AzureIdentityAccessTokenProvider) GetAuthorizationToken(ctx context.Context, url *u.URL, additionalAuthenticationContext map[string]interface{}) (string, error) {
	if !(*(p.allowedHostsValidator)).IsUrlHostValid(url) {
		return "", nil
	}
	if !strings.EqualFold(url.Scheme, "https") {
		return "", errors.New("url scheme must be https")
	}

	claims := ""

	if additionalAuthenticationContext != nil &&
		additionalAuthenticationContext[claimsKey] != nil {
		if rawClaims, ok := additionalAuthenticationContext[claimsKey].(string); ok {
			decodedClaims, err := base64.StdEncoding.DecodeString(rawClaims)
			if err != nil {
				return "", err
			}
			claims = string(decodedClaims)
			return "", errors.New("received a claim for CAE but azure identity doesn't support claims: " + claims + " https://github.com/Azure/azure-sdk-for-go/issues/14284")
		}
	}

	options := azpolicy.TokenRequestOptions{
		Scopes: p.scopes,
		//TODO pass the claims once the API is updated to support it https://github.com/Azure/azure-sdk-for-go/issues/14284
	}
	token, err := p.credential.GetToken(ctx, options)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

// GetAllowedHostsValidator returns the hosts validator.
func (p *AzureIdentityAccessTokenProvider) GetAllowedHostsValidator() *absauth.AllowedHostsValidator {
	return p.allowedHostsValidator
}
