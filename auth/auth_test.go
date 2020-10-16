package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/jwk"
	. "github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M)  {
	_ = godotenv.Load("../.env")
	os.Exit(m.Run())
}

func TestGetJWTToken(t *testing.T) {
	keySet := jwk.Set{}

	//Empty args
	token, details := GetJWTToken("", "", &keySet)
	NotNil(t, details)
	Equal(t, "Authorization token is invalid! token contains an invalid number of segments", details.Detail)
	Nil(t, token)

	tokenFromRequest := jwt.NewWithClaims(jwt.SigningMethodRS256, &AWSCognitoClaims{})

	//Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 500)
	NoError(t, err)

	signingString, err := tokenFromRequest.SignedString(privateKey)
	NoError(t, err)

	token, details = GetJWTToken("", signingString, &keySet)
	NotNil(t, details)
	Equal(t, "Authorization token is invalid! token header doesn't contain `kid` attribute", details.Detail)
	Nil(t, token)

	//Fill token's header `kid`
	tokenFromRequest.Header = make(map[string]interface{})
	tokenFromRequest.Header[jwk.KeyIDKey] = "ID"
	signingString, err = tokenFromRequest.SignedString(privateKey)
	NoError(t, err)

	token, details = GetJWTToken("", signingString, &keySet)
	NotNil(t, details)
	Equal(t, "Authorization token is invalid! signing method (alg) is unspecified.", details.Detail)
	Nil(t, token)

	//Fill token's header `alg`
	tokenFromRequest.Header[jwk.AlgorithmKey] = "RS256"
	signingString, err = tokenFromRequest.SignedString(privateKey)
	NoError(t, err)

	token, details = GetJWTToken("", signingString, &keySet)
	NotNil(t, details)
	Equal(t, "Authorization token is invalid! public key set doesn't contain requested public key. Key ID not found", details.Detail)
	Nil(t, token)

	//Get jwk key from private key
	publicKey, err := jwk.New(privateKey)
	NoError(t, err)

	err = publicKey.Set(jwk.KeyIDKey, "ID")
	NoError(t, err)

	keySet.Keys = make([]jwk.Key, 0, 1)
	keySet.Keys = append(keySet.Keys, publicKey)

	token, details = GetJWTToken("", signingString, &keySet)
	NotNil(t, details)
	Equal(t, "Authorization token is invalid! key is of invalid type", details.Detail)
	Nil(t, token)

	publicKey, err = jwk.New(privateKey.Public())
	NoError(t, err)

	err = publicKey.Set(jwk.KeyIDKey, "ID")
	NoError(t, err)

	keySet.Keys[0] = publicKey
	token, details = GetJWTToken("", signingString, &keySet)
	Nil(t, details)
	NotNil(t, token)
}

func TestGetPublicKeySet(t *testing.T) {
	set, err := GetPublicKeySet("", "")
	Error(t, err)
	Nil(t, set)

	set, err = GetPublicKeySet(os.Getenv("TEST_REGION"), os.Getenv("TEST_POOL_ID"))
	NoError(t, err)
	NotNil(t, set)
}

func TestVerifyJWT(t *testing.T) {
	keySet := jwk.Set{}
	claims, problem := VerifyJWT("", &keySet, "")
	NotNil(t, problem)
	Nil(t, claims)

	tokenFromRequest := jwt.NewWithClaims(jwt.SigningMethodRS256, &AWSCognitoClaims{})

	key, err := rsa.GenerateKey(rand.Reader, 500)
	NoError(t, err)
	signingString, err := tokenFromRequest.SignedString(key)
	NoError(t, err)

	publicKey, err := jwk.New(key.Public())
	NoError(t, err)

	err = publicKey.Set(jwk.KeyIDKey, "ID")
	NoError(t, err)

	keySet.Keys = make([]jwk.Key, 0, 1)
	keySet.Keys = append(keySet.Keys, publicKey)

	claims, problem = VerifyJWT(signingString, &keySet, "")
	NotNil(t, problem)
	Nil(t, claims)

	//Fill token's header
	tokenFromRequest.Header = make(map[string]interface{})
	tokenFromRequest.Header[jwk.KeyIDKey] = "ID"
	tokenFromRequest.Header[jwk.AlgorithmKey] = "RS256"
	signingString, err = tokenFromRequest.SignedString(key)
	NoError(t, err)

	claims, problem = VerifyJWT(signingString, &keySet, "")
	Nil(t, problem)
	NotNil(t, claims)
}

func Test_getKidFromToken(t *testing.T) {
	token := jwt.Token{}
	kid, err := getKidFromToken(&token)
	Error(t, err)
	Empty(t, kid)

	token.Method = &jwt.SigningMethodRSAPSS{}
	kid, err = getKidFromToken(&token)
	EqualError(t, err, fmt.Sprintf("unexpected token signing method: %v", nil))
	Empty(t, kid)

	token.Method = &jwt.SigningMethodRSA{}
	kid, err = getKidFromToken(&token)
	EqualError(t, err, "token header doesn't contain `kid` attribute")
	Empty(t, kid)

	token.Header = make(map[string]interface{})
	token.Header[jwk.KeyIDKey] = "ID"
	kid, err = getKidFromToken(&token)
	NoError(t, err)
	Equal(t, kid, "ID")
}

func Test_getTokenClaims(t *testing.T) {
	token := jwt.Token{}
	claims, err := getTokenClaims(&token)
	EqualError(t, err, "failed to get claims from the ID JWT token")
	Nil(t, claims)

	token.Claims = &AWSCognitoClaims{}
	claims, err = getTokenClaims(&token)
	NoError(t, err)
	NotNil(t, claims)
}

func Test_parseKeys(t *testing.T) {
	token := &jwt.Token{}
	key, err := parseKeys("", nil)(token)
	EqualError(t, err, "failed to get claims from the ID JWT token")
	Nil(t, key)

	token.Claims = &AWSCognitoClaims{}
	key, err = parseKeys("", nil)(token)
	EqualError(t, err, "unexpected token signing method: <nil>")
	Nil(t, key)

	token.Method = &jwt.SigningMethodRSA{}
	key, err = parseKeys("", nil)(token)
	EqualError(t, err, "token header doesn't contain `kid` attribute")
	Nil(t, key)

	token.Header = make(map[string]interface{})
	token.Header[jwk.KeyIDKey] = "ID"
	keySet := &jwk.Set{}
	key, err = parseKeys("", keySet)(token)
	EqualError(t, err, fmt.Sprintf("public key set doesn't contain requested public key. Key %v not found", token.Header[jwk.KeyIDKey]))
	Nil(t, key)

	publicKey := jwk.NewRSAPublicKey()
	err = publicKey.Set(jwk.KeyIDKey, "ID")
	NoError(t, err)
	keySet.Keys = make([]jwk.Key, 0, 1)
	keySet.Keys = append(keySet.Keys, publicKey)
	key, err = parseKeys("", keySet)(token)
	NoError(t, err)
	NotNil(t, key)
}

func Test_validateAud(t *testing.T) {
	token := &jwt.Token{}
	err := validateAud(token, "")
	Error(t, err)

	token.Claims = &AWSCognitoClaims{}
	err = validateAud(token, "11")
	EqualError(t, err, "token claims doesn't contain correct `aud` value")

	token.Claims = &AWSCognitoClaims{Aud: "11"}
	err = validateAud(token, "11")
	NoError(t, err)
}
