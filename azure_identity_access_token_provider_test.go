package microsoft_kiota_authentication_azure

import (
	"context"
	u "net/url"
	"testing"

	azcore "github.com/Azure/azure-sdk-for-go/sdk/azcore"
	policy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	assert "github.com/stretchr/testify/assert"
)

type MockTokenCredential struct {
	TokenValue         string
	LastRequestOptions policy.TokenRequestOptions
}

func (m *MockTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	m.LastRequestOptions = options
	return azcore.AccessToken{
		Token: m.TokenValue,
	}, nil
}

func TestAddsTokenOnValidHost(t *testing.T) {
	provider, err := NewAzureIdentityAccessTokenProvider(&MockTokenCredential{TokenValue: "token"})
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	token, err := provider.GetAuthorizationToken(context.Background(), &u.URL{Host: "graph.microsoft.com", Scheme: "https"}, nil)
	assert.Nil(t, err)
	assert.Equal(t, "token", token)
}

func TestAddsTokenOnValidHostFromParse(t *testing.T) {
	provider, err := NewAzureIdentityAccessTokenProvider(&MockTokenCredential{TokenValue: "token"})
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	url, err := u.Parse("https://graph.microsoft.com")
	assert.Nil(t, err)

	token, err := provider.GetAuthorizationToken(context.Background(), url, nil)
	assert.Nil(t, err)
	assert.Equal(t, "token", token)
}

func TestDoesntAddTokenOnDifferentHost(t *testing.T) {
	provider, err := NewAzureIdentityAccessTokenProviderWithScopesAndValidHosts(&MockTokenCredential{TokenValue: "token"}, []string{}, []string{"graph.microsoft.com"})
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	token, err := provider.GetAuthorizationToken(context.Background(), &u.URL{Host: "differenthost.com", Scheme: "https"}, nil)
	assert.Nil(t, err)
	assert.Empty(t, token)
}

func TestDoesntAddTokenOnHttp(t *testing.T) {
	provider, err := NewAzureIdentityAccessTokenProvider(&MockTokenCredential{TokenValue: "token"})
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	token, err := provider.GetAuthorizationToken(context.Background(), &u.URL{Host: "differenthost.com", Scheme: "http"}, nil)
	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestAddsTokenOnHttpLocalhost(t *testing.T) {
	for _, host := range LocalhostStrings {
		provider, err := NewAzureIdentityAccessTokenProvider(&MockTokenCredential{TokenValue: "token"})
		assert.Nil(t, err)
		assert.NotNil(t, provider)

		token, err := provider.GetAuthorizationToken(context.Background(), &u.URL{Host: host, Scheme: "http"}, nil)
		assert.Nil(t, err)
		assert.Equal(t, "token", token)
	}
}

func TestDisablesCae(t *testing.T) {
	mockCredential := &MockTokenCredential{TokenValue: "token"}
	provider, err := NewAzureIdentityAccessTokenProviderWithScopesAndValidHostsAndObservabilityOptionsAndIsCaeEnabled(mockCredential, nil, nil, ObservabilityOptions{}, false)
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	url, err := u.Parse("https://graph.microsoft.com")
	assert.Nil(t, err)

	_, err = provider.GetAuthorizationToken(context.Background(), url, nil)
	assert.NoError(t, err)
	assert.False(t, mockCredential.LastRequestOptions.EnableCAE)
}

func TestAddsClaimsToTokenRequest(t *testing.T) {
	mockCredential := &MockTokenCredential{TokenValue: "token"}
	provider, err := NewAzureIdentityAccessTokenProvider(mockCredential)
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	url, err := u.Parse("https://graph.microsoft.com")
	assert.Nil(t, err)

	additionalContext := make(map[string]interface{})
	additionalContext["claims"] = "eyJhY2Nlc3NfdG9rZW4iOnsibmJmIjp7ImVzc2VudGlhbCI6dHJ1ZSwgInZhbHVlIjoiMTY1MjgxMzUwOCJ9fX0="
	token, err := provider.GetAuthorizationToken(context.Background(), url, additionalContext)
	assert.NoError(t, err)
	assert.Equal(t, "token", token)
	assert.True(t, mockCredential.LastRequestOptions.EnableCAE)
	assert.JSONEq(t, `{"access_token":{"nbf":{"essential":true, "value":"1652813508"}}}`, mockCredential.LastRequestOptions.Claims)
}
