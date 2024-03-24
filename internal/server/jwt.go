package server

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
	ID string `json:"id"`
}

// creates a jwt token with custom claim containing users' oauth id as part of the claim
func createToken(uid string) (string, error) {
	customClaim := MyCustomClaims{
		ID: uid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 60)),
			Issuer:    "boonsapp",
		},
	}

	fmt.Println("%+v", customClaim)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaim)

	ss, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("Failed to sign token from createToken: %w", err)
	}
	return ss, nil
}
