package auth

import (
	"fmt"

	"github.com/Kviky/errors"
	"github.com/Kviky/errors/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

// AWSCognitoClaims - AWS Cognito ID JWT token custom claims
// We want to get some details from the ID JWT token, attributes like custom:userid or cognito:username.
// Let's add Aud, so we can verify, if it match our App client ID in AWS Cognito User Pool
// You can also add user identifier (f.e. username) to check additional details in DB
type AWSCognitoClaims struct {
	Aud      string `json:"aud"`
	Name     string `json:"name"`
	Username string `json:"cognito:username"`
	Userid   string `json:"custom:userid"`

	jwt.StandardClaims
}

// GetPublicKeySet - returns jwk set object
func GetPublicKeySet(cognitoRegion, cognitoPoolID string) (*jwk.Set, error) {
	// url - AWS Cognito Public keys url
	// "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_cTauv7zGJ/.well-known/jwks.json"
	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
		cognitoRegion, cognitoPoolID)

	// Download public keys information
	// .Fetch method of https://github.com/lestrrat-go/jwx
	publicKeySet, err := jwk.Fetch(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys: %w", err)
	}

	return publicKeySet, nil
}

// GetJWTToken - returns jwt token object or problem details
func GetJWTToken(cognitoAppID, tokenPrincipal string, publicKeySet *jwk.Set) (*jwt.Token, *models.ProblemDetails) {
	// Parse token - it's actually doing parsing, validation and returning a token.
	// Use .Parse or .ParseWithClaims methods from https://github.com/dgrijalva/jwt-go
	token, err := jwt.ParseWithClaims(tokenPrincipal, &AWSCognitoClaims{}, parseKeys(cognitoAppID, publicKeySet))
	if err != nil {
		// Catch the error
		// This place can throw token expiration error too
		problem := errors.CreateProblemDetails(errors.InvalidAuthToken)

		// extend problem.Details with the error report from the ParseWithClaims function
		problem.Detail = fmt.Sprintf("%s %v", problem.Detail, err)
		return nil, problem
	}

	return token, nil
}

func parseKeys(cognitoAppID string, publicKeySet *jwk.Set) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		err := validateAud(token, cognitoAppID)
		if err != nil {
			return nil, err
		}

		kid, err := getKidFromToken(token)
		if err != nil {
			return nil, err
		}

		keys := publicKeySet.LookupKeyID(kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("public key set doesn't contain requested public key. Key %v not found", kid)
		}

		// In this case, we are returning only one key = keys[0]
		// Return token key as []byte{string} type
		var tokenKey interface{}
		if err = keys[0].Raw(&tokenKey); err != nil {
			return nil, fmt.Errorf("failed to create raw token key: %w", err)
		}

		return tokenKey, nil
	}
}

func getKidFromToken(token *jwt.Token) (string, error) {
	// Verify if the token was signed with correct signing method
	// AWS Cognito is using RSA256 in this case
	_, ok := token.Method.(*jwt.SigningMethodRSA)
	if !ok {
		return "", fmt.Errorf("unexpected token signing method: %v", token.Header["alg"])
	}

	// Get "kid" value from token header
	// "kid" is shorthand for Key ID
	kid, ok := token.Header[jwk.KeyIDKey].(string)
	if !ok {
		return "", fmt.Errorf("token header doesn't contain `kid` attribute")
	}

	return kid, nil
}

// validateAud checks jwt token
// Get claims (user details) from the jwt token.
// Claims are part of the AWSCognito custom attributes
// Verify if `aud` attribute is valid
func validateAud(token *jwt.Token, cognitoAppID string) error {
	claims, err := getTokenClaims(token)
	if err != nil {
		return err
	}

	if claims.Aud != cognitoAppID {
		return fmt.Errorf("token claims doesn't contain correct `aud` value")
	}

	return nil
}

// getTokenClaims - helper function to get claims from the ID JWT Token
func getTokenClaims(jwtToken *jwt.Token) (*AWSCognitoClaims, error) {
	// Get claims (user details) from the jwt token. Claims are part of the AWSCognito custom attributes
	claims, ok := jwtToken.Claims.(*AWSCognitoClaims)
	if !ok {
		return nil, fmt.Errorf("failed to get claims from the ID JWT token")
	}

	return claims, nil
}

// VerifyJWT - main function to verify validity of JWToken
func VerifyJWT(principal string, publicKeysSet *jwk.Set, cognitoAppID string) (
	claims *AWSCognitoClaims, problem *models.ProblemDetails) {
	// DONE
	// [x] validate token
	// [x] check expiration
	// [x] Verify audience "aud" matches the app client ID
	jwtToken, problem := GetJWTToken(cognitoAppID, principal, publicKeysSet)
	if problem != nil {
		return nil, problem
	}

	if !jwtToken.Valid {
		return nil, nil
	}

	// Get claims (user details) from the jwt token. Claims are part of the AWSCognito custom attributes
	claims, err := getTokenClaims(jwtToken)
	if err != nil {
		problem := errors.CreateProblemDetails(errors.InvalidAuthToken)
		problem.Detail = fmt.Sprintf("%s %s", problem.Detail, err)
		return nil, problem
	}

	return claims, nil
}
