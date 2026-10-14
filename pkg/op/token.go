package op

import (
	"context"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type TokenCreator interface {
	Storage() Storage
	Crypto() Crypto
}

// TokenCreatorOptions can optionally be implemented by a [TokenCreator]
// (the [Provider] does, driven by [Config]) to opt in to stricter token formats.
// Creators that do not implement it get the historic behavior.
type TokenCreatorOptions interface {
	// AccessTokenTypeRFC9068 reports whether JWT access tokens are signed
	// with the JOSE header typ "at+jwt" (RFC 9068) instead of "JWT".
	AccessTokenTypeRFC9068() bool
	// IDTokenAudienceClientIDOnly reports whether the audience of ID tokens
	// is restricted to the client ID, instead of the request's audience
	// (which usually carries the resource server of the access token).
	IDTokenAudienceClientIDOnly() bool
}

func accessTokenTypeRFC9068(creator TokenCreator) bool {
	o, ok := creator.(TokenCreatorOptions)
	return ok && o.AccessTokenTypeRFC9068()
}

func idTokenAudienceClientIDOnly(creator TokenCreator) bool {
	o, ok := creator.(TokenCreatorOptions)
	return ok && o.IDTokenAudienceClientIDOnly()
}

type TokenRequest interface {
	GetSubject() string
	GetAudience() []string
	GetScopes() []string
}

type AccessTokenClient interface {
	GetID() string
	ClockSkew() time.Duration
	RestrictAdditionalAccessTokenScopes() func(scopes []string) []string
	GrantTypes() []oidc.GrantType
}

func CreateTokenResponse(ctx context.Context, request IDTokenRequest, client Client, creator TokenCreator, createAccessToken bool, code, refreshToken string) (*oidc.AccessTokenResponse, error) {
	ctx, span := Tracer.Start(ctx, "CreateTokenResponse")
	defer span.End()

	var accessToken, newRefreshToken string
	var validity time.Duration
	if createAccessToken {
		var err error
		accessToken, newRefreshToken, validity, err = CreateAccessToken(ctx, request, client.AccessTokenType(), creator, client, refreshToken)
		if err != nil {
			return nil, err
		}
	}
	idToken, err := createIDToken(ctx, IssuerFromContext(ctx), request, client.IDTokenLifetime(), accessToken, code, creator.Storage(), client, idTokenAudienceClientIDOnly(creator))
	if err != nil {
		return nil, err
	}

	var state string
	if authRequest, ok := request.(AuthRequest); ok {
		err = creator.Storage().DeleteAuthRequest(ctx, authRequest.GetID())
		if err != nil {
			return nil, err
		}
		// only implicit flow requires state to be returned.
		if code == "" {
			state = authRequest.GetState()
		}
	}

	exp := uint64(validity.Seconds())
	return &oidc.AccessTokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: newRefreshToken,
		TokenType:    oidc.BearerToken,
		ExpiresIn:    exp,
		State:        state,
		Scope:        request.GetScopes(),
	}, nil
}

// createTokens delegates token creation to the appropriate storage method based on
// the request type and requirements. It returns an access token ID and expiration
// in all cases, but the refresh token handling varies:
//   - When needsRefreshToken() returns true: calls CreateAccessAndRefreshTokens,
//     which returns both tokens. The newRefreshToken will contain the actual token value.
//   - When needsRefreshToken() returns false: calls CreateAccessToken only.
//     The newRefreshToken will be an empty string in this case.
func createTokens(ctx context.Context, tokenRequest TokenRequest, storage Storage, refreshToken string, client AccessTokenClient) (id, newRefreshToken string, exp time.Time, err error) {
	ctx, span := Tracer.Start(ctx, "createTokens")
	defer span.End()

	if needsRefreshToken(tokenRequest, client) {
		return storage.CreateAccessAndRefreshTokens(ctx, tokenRequest, refreshToken)
	}
	id, exp, err = storage.CreateAccessToken(ctx, tokenRequest)
	return id, "", exp, err
}

func needsRefreshToken(tokenRequest TokenRequest, client AccessTokenClient) bool {
	switch req := tokenRequest.(type) {
	case AuthRequest:
		return slices.Contains(req.GetScopes(), oidc.ScopeOfflineAccess) && req.GetResponseType() == oidc.ResponseTypeCode && ValidateGrantType(client, oidc.GrantTypeRefreshToken)
	case TokenExchangeRequest:
		return req.GetRequestedTokenType() == oidc.RefreshTokenType
	case RefreshTokenRequest:
		return true
	case *DeviceAuthorizationState:
		return slices.Contains(req.GetScopes(), oidc.ScopeOfflineAccess) && ValidateGrantType(client, oidc.GrantTypeRefreshToken)
	default:
		return false
	}
}

// CreateAccessToken creates an access token and may return a refresh token from storage.
// This function always creates the access token using the ID returned from storage.
// The refresh token is obtained from the storage layer and passed through unchanged.
// Whether a refresh token is included depends on the request:
//   - Authorization code flow with offline_access scope: returns refresh token
//   - Refresh token grant (rotation): returns new refresh token
//   - Client credentials, implicit flow: returns empty string
//
// The function returns both tokens to support all flows with a single signature.
func CreateAccessToken(ctx context.Context, tokenRequest TokenRequest, accessTokenType AccessTokenType, creator TokenCreator, client AccessTokenClient, refreshToken string) (accessToken, newRefreshToken string, validity time.Duration, err error) {
	ctx, span := Tracer.Start(ctx, "CreateAccessToken")
	defer span.End()

	id, newRefreshToken, exp, err := createTokens(ctx, tokenRequest, creator.Storage(), refreshToken, client)
	if err != nil {
		return "", "", 0, err
	}
	var clockSkew time.Duration
	if client != nil {
		clockSkew = client.ClockSkew()
	}
	validity = exp.Add(clockSkew).Sub(time.Now().UTC())
	if accessTokenType == AccessTokenTypeJWT {
		accessToken, err = createJWT(ctx, IssuerFromContext(ctx), tokenRequest, exp, id, client, creator.Storage(), accessTokenTypeRFC9068(creator))
		return accessToken, newRefreshToken, validity, err
	}
	_, span = Tracer.Start(ctx, "CreateBearerToken")
	accessToken, err = CreateBearerToken(id, tokenRequest.GetSubject(), creator.Crypto())
	span.End()
	return accessToken, newRefreshToken, validity, err
}

func CreateBearerToken(tokenID, subject string, crypto Encrypter) (string, error) {
	return crypto.Encrypt(tokenID + ":" + subject)
}

type TokenActorRequest interface {
	GetActor() *oidc.ActorClaims
}

// CreateJWT creates a JWT access token with the JOSE header typ "JWT".
// Use [Config.AccessTokenTypeRFC9068] to issue "at+jwt" tokens through the [Provider].
func CreateJWT(ctx context.Context, issuer string, tokenRequest TokenRequest, exp time.Time, id string, client AccessTokenClient, storage Storage) (string, error) {
	return createJWT(ctx, issuer, tokenRequest, exp, id, client, storage, false)
}

func createJWT(ctx context.Context, issuer string, tokenRequest TokenRequest, exp time.Time, id string, client AccessTokenClient, storage Storage, rfc9068 bool) (string, error) {
	ctx, span := Tracer.Start(ctx, "CreateJWT")
	defer span.End()

	claims := oidc.NewAccessTokenClaims(issuer, tokenRequest.GetSubject(), tokenRequest.GetAudience(), exp, id, client.GetID(), client.ClockSkew())
	if client != nil {
		restrictedScopes := client.RestrictAdditionalAccessTokenScopes()(tokenRequest.GetScopes())

		var (
			privateClaims map[string]any
			err           error
		)

		tokenExchangeRequest, okReq := tokenRequest.(TokenExchangeRequest)
		teStorage, okStorage := storage.(TokenExchangeStorage)
		if okReq && okStorage {
			privateClaims, err = teStorage.GetPrivateClaimsFromTokenExchangeRequest(
				ctx,
				tokenExchangeRequest,
			)
		} else {
			if fromRequest, ok := storage.(CanGetPrivateClaimsFromRequest); ok {
				privateClaims, err = fromRequest.GetPrivateClaimsFromRequest(ctx, tokenRequest, removeUserinfoScopes(restrictedScopes))
			} else {
				privateClaims, err = storage.GetPrivateClaimsFromScopes(ctx, tokenRequest.GetSubject(), client.GetID(), removeUserinfoScopes(restrictedScopes))
			}
		}

		if err != nil {
			return "", err
		}
		claims.Claims = privateClaims
	}
	if actorReq, ok := tokenRequest.(TokenActorRequest); ok {
		claims.Actor = actorReq.GetActor()
	}
	signingKey, err := storage.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	typ := jose.ContentType(JWTType)
	if rfc9068 {
		typ = AccessTokenJWTType
	}
	signer, err := SignerFromKeyWithType(signingKey, typ)
	if err != nil {
		return "", err
	}
	return crypto.Sign(claims, signer)
}

type IDTokenRequest interface {
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
}

func CreateIDToken(ctx context.Context, issuer string, request IDTokenRequest, validity time.Duration, accessToken, code string, storage Storage, client Client) (string, error) {
	return createIDToken(ctx, issuer, request, validity, accessToken, code, storage, client, false)
}

// createIDToken creates the ID token. If audClientIDOnly is set, the audience is
// exactly [client_id] and the request's audience is ignored.
func createIDToken(ctx context.Context, issuer string, request IDTokenRequest, validity time.Duration, accessToken, code string, storage Storage, client Client, audClientIDOnly bool) (string, error) {
	ctx, span := Tracer.Start(ctx, "CreateIDToken")
	defer span.End()

	exp := time.Now().UTC().Add(client.ClockSkew()).Add(validity)
	var acr, nonce string
	if authRequest, ok := request.(AuthRequest); ok {
		acr = authRequest.GetACR()
		nonce = authRequest.GetNonce()
	}
	audience := request.GetAudience()
	if audClientIDOnly {
		audience = nil // NewIDTokenClaims appends the client ID
	}
	claims := oidc.NewIDTokenClaims(issuer, request.GetSubject(), audience, exp, request.GetAuthTime(), nonce, acr, request.GetAMR(), request.GetClientID(), client.ClockSkew())
	if actorReq, ok := request.(TokenActorRequest); ok {
		claims.Actor = actorReq.GetActor()
	}

	scopes := client.RestrictAdditionalIdTokenScopes()(request.GetScopes())
	signingKey, err := storage.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	if accessToken != "" {
		atHash, err := oidc.ClaimHash(accessToken, signingKey.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.AccessTokenHash = atHash
		if !client.IDTokenUserinfoClaimsAssertion() {
			scopes = removeUserinfoScopes(scopes)
		}
	}

	tokenExchangeRequest, okReq := request.(TokenExchangeRequest)
	teStorage, okStorage := storage.(TokenExchangeStorage)
	if okReq && okStorage {
		userInfo := new(oidc.UserInfo)
		err := teStorage.SetUserinfoFromTokenExchangeRequest(ctx, userInfo, tokenExchangeRequest)
		if err != nil {
			return "", err
		}
		claims.SetUserInfo(userInfo)
	} else if len(scopes) > 0 {
		userInfo := new(oidc.UserInfo)
		err := storage.SetUserinfoFromScopes(ctx, userInfo, request.GetSubject(), request.GetClientID(), scopes)
		if err != nil {
			return "", err
		}
		if fromRequest, ok := storage.(CanSetUserinfoFromRequest); ok {
			err := fromRequest.SetUserinfoFromRequest(ctx, userInfo, request, scopes)
			if err != nil {
				return "", err
			}
		}
		claims.SetUserInfo(userInfo)
	}
	if code != "" {
		codeHash, err := oidc.ClaimHash(code, signingKey.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.CodeHash = codeHash
	}
	signer, err := SignerFromKey(signingKey)
	if err != nil {
		return "", err
	}
	return crypto.Sign(claims, signer)
}

func removeUserinfoScopes(scopes []string) []string {
	newScopeList := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile,
			oidc.ScopeEmail,
			oidc.ScopeAddress,
			oidc.ScopePhone:
			continue
		default:
			newScopeList = append(newScopeList, scope)
		}
	}
	return newScopeList
}
