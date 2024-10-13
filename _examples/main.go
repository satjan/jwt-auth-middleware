package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/satjan/jwt-auth-middleware"
	"time"
)

func main() {
	jwtConfig := jwtmiddleware.Config{
		SecretKey:         "secret",
		RefreshSecretKey:  "refresh-secret",
		Issuer:            "my-app",
		Aud:               "my-audience",
		ExpirationHours:   24,
		RefreshExpiration: 720 * time.Hour,
	}

	jwtWrapper := &jwtmiddleware.JWTWrapper{Config: jwtConfig}
	authMiddleware := jwtmiddleware.NewAuthMiddleware(jwtWrapper)

	// Protecting Routes
	app := fiber.New()
	app.Use(authMiddleware.AuthRequired)
}
