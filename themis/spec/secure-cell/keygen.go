package cell

import "crypto/rand"

const recommendedSymmetricKeyLength = 32

// NewSymmetricKey generates a new symmetric key for Secure Cell.
func NewSymmetricKey() []byte {
	key := make([]byte, recommendedSymmetricKeyLength)
	_, err := rand.Read(key)
	if err != nil {
		panic(err.Error())
	}
	return key
}
