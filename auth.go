package jwtmiddleware

import (
	"github.com/gofiber/fiber/v2"
	"net/http"
	"strings"
)

type AuthMiddleware struct {
	jwt *JWTWrapper
}

// NewAuthMiddleware initializes the JWT middleware with provided configuration.
func NewAuthMiddleware(jwt *JWTWrapper) *AuthMiddleware {
	return &AuthMiddleware{jwt}
}

// AuthRequired checks for a valid token and sets user ID in the context.
func (c *AuthMiddleware) AuthRequired(ctx *fiber.Ctx) error {
	authorization := ctx.Get("Authorization")
	if authorization == "" {
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing authorization header"})
	}

	token := strings.TrimPrefix(authorization, "Bearer ")
	if token == authorization { // Token not prefixed with "Bearer "
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token format"})
	}

	claims, err := c.jwt.ValidateToken(token, false)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token", "details": err.Error()})
	}

	ctx.Set("userId", claims.UserID.String())
	return ctx.Next()
}
