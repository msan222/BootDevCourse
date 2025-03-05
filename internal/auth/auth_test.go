package auth

//Unit Tests for auth JWT function
import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Unit Test
func TestMakeJWTAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "mysecret"
	expiresIn := time.Minute * 5

	//Generate JWT
	token, err := MakeJWT(userID, secret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	//Validate the JWT
	validatedUserID, err := ValidateJWT(token, secret)
	assert.NoError(t, err)
	assert.Equal(t, userID, validatedUserID)

	//Test invalid secret
	_, err = ValidateJWT(token, "wrongsecret")
	assert.Error(t, err)

	//Test expiration
	expiredToken, err := MakeJWT(userID, secret, -time.Minute)
	assert.NoError(t, err)
	_, err = ValidateJWT(expiredToken, secret)
	assert.Error(t, err)
}
