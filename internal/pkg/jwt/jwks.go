package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type JwtVerifier struct {
	keyFunc   keyfunc.Keyfunc
	issuer    string
	audiences []string
}

type Config struct {
	JwksURL   []string
	Issuer    string
	Audiences []string
}

func NewVerifier(ctx context.Context, cfg Config) (*JwtVerifier, error) {
	k, err := keyfunc.NewDefaultCtx(ctx, cfg.JwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyfunc: %w", err)
	}

	return &JwtVerifier{keyFunc: k, issuer: cfg.Issuer, audiences: cfg.Audiences}, nil
}

func (v *JwtVerifier) Verify(ctx context.Context, tokenString string) (*jwt.Token, error) {
	parsed, err := jwt.Parse(
		tokenString,
		v.keyFunc.Keyfunc,
		jwt.WithValidMethods([]string{
			jwt.SigningMethodRS256.Alg(),
			jwt.SigningMethodEdDSA.Alg(),
		}),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(1*time.Minute),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audiences...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return parsed, nil
}
