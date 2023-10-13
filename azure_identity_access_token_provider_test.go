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
	TokenValue string
}

func (m *MockTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
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

func TestAddsClaimsToTokenRequest(t *testing.T) {
	provider, err := NewAzureIdentityAccessTokenProvider(&MockTokenCredential{TokenValue: "token"})
	assert.Nil(t, err)
	assert.NotNil(t, provider)

	url, err := u.Parse("https://graph.microsoft.com")
	assert.Nil(t, err)

	additionalContext := make(map[string]interface{})
	additionalContext["claims"] = "eyJhY2Nlc3NfdG9rZW4iOnsibmJmIjp7ImVzc2VudGlhbCI6dHJ1ZSwgInZhbHVlIjoiMTY1MjgxMzUwOCJ9fX0="
	token, err := provider.GetAuthorizationToken(context.Background(), url, additionalContext)
	assert.NotNil(t, err) //TODO update when azure identity has added the field
	assert.Empty(t, token)
}
