package op_test

import (
	"context"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const testResource = "https://api.example.com/"

// resourceAuthRequest simulates a storage that sets the audience of the
// request to a resource server (RFC 8707), as is common for JWT access tokens.
type resourceAuthRequest struct {
	op.AuthRequest
}

func (resourceAuthRequest) GetAudience() []string { return []string{testResource} }

func TestTokenFormat(t *testing.T) {
	tests := []struct {
		name         string
		rfc9068      bool
		idAudClient  bool
		wantATTyp    string
		wantIDTyp    string
		wantIDAud    []string
		wantAccesAud []string
	}{
		{
			name:         "defaults keep historic behavior",
			wantATTyp:    "JWT",
			wantIDTyp:    "JWT",
			wantIDAud:    []string{testResource, "web"},
			wantAccesAud: []string{testResource},
		},
		{
			name:         "access token typ at+jwt",
			rfc9068:      true,
			wantATTyp:    "at+jwt",
			wantIDTyp:    "JWT",
			wantIDAud:    []string{testResource, "web"},
			wantAccesAud: []string{testResource},
		},
		{
			name:         "id token audience client id only",
			idAudClient:  true,
			wantATTyp:    "JWT",
			wantIDTyp:    "JWT",
			wantIDAud:    []string{"web"},
			wantAccesAud: []string{testResource},
		},
		{
			name:         "both options",
			rfc9068:      true,
			idAudClient:  true,
			wantATTyp:    "at+jwt",
			wantIDTyp:    "JWT",
			wantIDAud:    []string{"web"},
			wantAccesAud: []string{testResource},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := *testConfig
			cfg.AccessTokenTypeRFC9068 = tt.rfc9068
			cfg.IDTokenAudienceClientIDOnly = tt.idAudClient
			provider := newTestProvider(&cfg)
			ctx := op.ContextWithIssuer(context.Background(), testIssuer)
			st := provider.Storage().(routesTestStorage)

			client, err := st.GetClientByClientID(ctx, "web")
			require.NoError(t, err)
			authReq, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
				ClientID:     "web",
				RedirectURI:  "https://example.com",
				Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
				ResponseType: oidc.ResponseTypeCode,
			}, "id1")
			require.NoError(t, err)
			st.AuthRequestDone(authReq.GetID())
			req := resourceAuthRequest{authReq}

			// the example client issues bearer tokens; JWT access tokens are what we test
			jwtClient := jwtAccessTokenClient{client}
			resp, err := op.CreateTokenResponse(ctx, req, jwtClient, provider, true, "", "")
			require.NoError(t, err)

			at := decodeJWT(t, ctx, provider, resp.AccessToken)
			id := decodeJWT(t, ctx, provider, resp.IDToken)

			assert.Equal(t, tt.wantATTyp, at.typ)
			assert.Equal(t, tt.wantIDTyp, id.typ)
			assert.ElementsMatch(t, tt.wantAccesAud, at.aud)
			assert.ElementsMatch(t, tt.wantIDAud, id.aud)

			// at_hash commits to the exact access token string
			wantHash, err := oidc.ClaimHash(resp.AccessToken, jose.RS256)
			require.NoError(t, err)
			assert.Equal(t, wantHash, id.claims["at_hash"])
		})
	}
}

func TestAccessTokenResponseType(t *testing.T) {
	tests := []struct {
		name              string
		extension         bool
		tokenType         string
		createAccessToken bool
		wantTokenType     string
	}{
		{
			name:              "storage without extension",
			createAccessToken: true,
			wantTokenType:     "Bearer",
		},
		{
			name:              "DPoP access token",
			extension:         true,
			tokenType:         oidc.DPoPTokenType,
			createAccessToken: true,
			wantTokenType:     "DPoP",
		},
		{
			name:              "empty extension result",
			extension:         true,
			createAccessToken: true,
			wantTokenType:     "Bearer",
		},
		{
			name:          "no access token",
			extension:     true,
			tokenType:     oidc.DPoPTokenType,
			wantTokenType: "Bearer",
		},
	}
	for _, refresh := range []bool{false, true} {
		flow := "code exchange"
		if refresh {
			flow = "refresh"
		}
		t.Run(flow, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					cfg := *testConfig
					provider := newTestProvider(&cfg)
					type contextKey struct{}
					ctx := context.WithValue(context.Background(), contextKey{}, "token binding")
					ctx = op.ContextWithIssuer(ctx, testIssuer)
					st := provider.Storage().(routesTestStorage)

					client, err := st.GetClientByClientID(ctx, "web")
					require.NoError(t, err)
					authReq, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
						ClientID:     "web",
						RedirectURI:  "https://example.com",
						Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
						ResponseType: oidc.ResponseTypeCode,
					}, "id1")
					require.NoError(t, err)
					st.AuthRequestDone(authReq.GetID())
					client = tokenTypeRefreshClient{client}

					// Embedding Storage exposes only its required methods.
					creator := tokenTypeCreator{TokenCreator: provider, storage: struct{ op.Storage }{st}}
					var request op.IDTokenRequest = authReq
					code, refreshToken := "code", ""
					if refresh {
						initial, err := op.CreateTokenResponse(ctx, request, client, creator, true, code, "")
						require.NoError(t, err)
						require.NotEmpty(t, initial.RefreshToken)
						request, err = st.TokenRequestByRefreshToken(ctx, initial.RefreshToken)
						require.NoError(t, err)
						code, refreshToken = "", initial.RefreshToken
					}

					called := false
					if tt.extension {
						creator.storage = tokenTypeStorage{
							Storage: creator.storage,
							accessTokenType: func(ctx context.Context, gotRequest op.TokenRequest) string {
								called = true
								assert.Equal(t, "token binding", ctx.Value(contextKey{}))
								assert.Equal(t, request, gotRequest)
								return tt.tokenType
							},
						}
					}
					resp, err := op.CreateTokenResponse(ctx, request, client, creator, tt.createAccessToken, code, refreshToken)
					require.NoError(t, err)
					assert.Equal(t, tt.wantTokenType, resp.TokenType)
					assert.Equal(t, tt.extension && tt.createAccessToken, called)
					if tt.createAccessToken {
						assert.NotEmpty(t, resp.AccessToken)
					} else {
						assert.Empty(t, resp.AccessToken)
					}
				})
			}
		})
	}
}

type tokenTypeCreator struct {
	op.TokenCreator
	storage op.Storage
}

func (c tokenTypeCreator) Storage() op.Storage { return c.storage }

type tokenTypeStorage struct {
	op.Storage
	accessTokenType func(context.Context, op.TokenRequest) string
}

func (s tokenTypeStorage) AccessTokenType(ctx context.Context, request op.TokenRequest) string {
	return s.accessTokenType(ctx, request)
}

type tokenTypeRefreshClient struct{ op.Client }

func (tokenTypeRefreshClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

type jwtAccessTokenClient struct{ op.Client }

func (jwtAccessTokenClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

type decodedJWT struct {
	typ    string
	aud    []string
	claims map[string]any
}

func decodeJWT(t *testing.T, ctx context.Context, provider op.OpenIDProvider, token string) decodedJWT {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	keys, err := provider.Storage().KeySet(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	payload, err := jws.Verify(keys[0].Key())
	require.NoError(t, err, "signature must verify")

	typ, _ := jws.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
	var claims struct {
		Aud oidc.Audience `json:"aud"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	var all map[string]any
	require.NoError(t, json.Unmarshal(payload, &all))
	return decodedJWT{typ: typ, aud: claims.Aud, claims: all}
}
