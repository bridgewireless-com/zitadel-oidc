package op

import (
	"errors"

	jose "github.com/go-jose/go-jose/v4"
)

var ErrSignerCreationFailed = errors.New("signer creation failed")

type SigningKey interface {
	SignatureAlgorithm() jose.SignatureAlgorithm
	Key() any
	ID() string
}

const (
	// JWTType is the JOSE "typ" header used for ID tokens and, by default, access tokens.
	JWTType = "JWT"
	// AccessTokenJWTType is the JOSE "typ" header for JWT access tokens as defined in RFC 9068.
	AccessTokenJWTType = "at+jwt"
)

// SignerFromKey creates a signer with the JOSE "typ" header set to "JWT".
func SignerFromKey(key SigningKey) (jose.Signer, error) {
	return SignerFromKeyWithType(key, JWTType)
}

// SignerFromKeyWithType creates a signer with the JOSE "typ" header set to typ.
func SignerFromKeyWithType(key SigningKey, typ jose.ContentType) (jose.Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: key.SignatureAlgorithm(),
		Key: &jose.JSONWebKey{
			Key:   key.Key(),
			KeyID: key.ID(),
		},
	}, (&jose.SignerOptions{}).WithType(typ))
	if err != nil {
		return nil, ErrSignerCreationFailed // TODO: log / wrap error?
	}
	return signer, nil
}

type Key interface {
	ID() string
	Algorithm() jose.SignatureAlgorithm
	Use() string
	Key() any
}
