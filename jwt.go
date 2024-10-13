package jwtmiddleware

import (
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/google/uuid"
	"time"
)

// Config holds the JWT settings.
type Config struct {
	SecretKey         string
	RefreshSecretKey  string
	Issuer            string
	Aud               string
	ExpirationHours   int
	RefreshExpiration time.Duration
}

type JWTWrapper struct {
	Config Config
}

type JwtPayload struct {
	jwt.Payload
	UserID uuid.UUID `json:"userId,omitempty"`
}

// GenerateToken creates a new JWT token for a user.
func (w *JWTWrapper) GenerateToken(id uuid.UUID) (string, *jwt.Time, error) {
	hs := jwt.NewHS256([]byte(w.Config.SecretKey))
	now := time.Now()
	exp := time.Duration(w.Config.ExpirationHours) * time.Hour

	pl := JwtPayload{
		Payload: jwt.Payload{
			Issuer:         w.Config.Issuer,
			Subject:        w.Config.Aud,
			ExpirationTime: jwt.NumericDate(now.Add(exp)),
			IssuedAt:       jwt.NumericDate(now),
		},
		UserID: id,
	}

	token, err := jwt.Sign(pl, hs)
	if err != nil {
		return "", nil, err
	}

	return string(token), pl.Payload.ExpirationTime, nil
}

// ValidateToken verifies the JWT token.
func (w *JWTWrapper) ValidateToken(signedToken string, isRefresh bool) (*JwtPayload, error) {
	now := time.Now()
	pl := JwtPayload{}

	validatePayload := jwt.ValidatePayload(
		&pl.Payload,
		jwt.ExpirationTimeValidator(now),
		jwt.IssuerValidator(w.Config.Issuer),
		jwt.AudienceValidator([]string{w.Config.Aud}),
		jwt.IssuedAtValidator(now),
	)

	secretKey := w.Config.SecretKey
	if isRefresh {
		secretKey = w.Config.RefreshSecretKey
	}

	hs := jwt.NewHS256([]byte(secretKey))
	if _, err := jwt.Verify([]byte(signedToken), hs, &pl, validatePayload); err != nil {
		return nil, err
	}

	return &pl, nil
}

// GenerateRefreshToken creates a new refresh token for a user.
func (w *JWTWrapper) GenerateRefreshToken(userID uuid.UUID) (string, error) {
	hs := jwt.NewHS256([]byte(w.Config.RefreshSecretKey))
	now := time.Now()

	exp := w.Config.RefreshExpiration
	if exp == 0 {
		exp = 720 * time.Hour // Default to 1 month
	}

	pl := JwtPayload{
		Payload: jwt.Payload{
			Issuer:         w.Config.Issuer,
			Audience:       []string{w.Config.Aud},
			ExpirationTime: jwt.NumericDate(now.Add(exp)),
			IssuedAt:       jwt.NumericDate(now),
		},
		UserID: userID,
	}

	token, err := jwt.Sign(pl, hs)
	if err != nil {
		return "", err
	}

	return string(token), nil
}
