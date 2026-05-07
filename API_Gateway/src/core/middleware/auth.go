package middleware

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthClaims struct {
	SessionID string   `json:"sid"`
	Roles     []string `json:"roles"`

	jwt.RegisteredClaims
}

type AuthMiddleware struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

func NewAuthMiddleware(publicKeyPath string, issuer string, audience string) (*AuthMiddleware, error) {
	publicKeyPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return &AuthMiddleware{
		publicKey: publicKey,
		issuer:    issuer,
		audience:  audience,
	}, nil
}

func (m *AuthMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		rawToken, err := extractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid authorization header",
			})
			return
		}

		claims := &AuthClaims{}

		token, err := jwt.ParseWithClaims(
			rawToken,
			claims,
			func(token *jwt.Token) (interface{}, error) {
				if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
					return nil, errors.New("unexpected signing method")
				}

				return m.publicKey, nil
			},
			jwt.WithIssuer(m.issuer),
			jwt.WithAudience(m.audience),
		)

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		if claims.Subject == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "token does not contain user_id",
			})
			return
		}

		if claims.SessionID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "token does not contain session_id",
			})
			return
		}

		c.Set("user_id", claims.Subject)
		c.Set("session_id", claims.SessionID)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

func extractBearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("empty authorization header")
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid authorization header")
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization scheme")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("empty token")
	}

	return token, nil
}
