package cell

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestContextImprintMode(t *testing.T) {
	plaintext := []byte("secret message")
	context := []byte("Context Imprint needs a context")
	key := NewSymmetricKey()
	encrypted := EncryptWithContext(plaintext, key, context)
	decrypted := DecryptWithContext(encrypted, key, context)

	if len(encrypted) != len(decrypted) {
		t.Error("encrypted data must preserve length")
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data must be equal to plaintext")
	}
}

func TestContextImprintDoesNoErrorChecks(t *testing.T) {
	plaintext := []byte("secret message")
	key := NewSymmetricKey()
	encrypted := EncryptWithContext(plaintext, key, []byte("alpha"))
	decrypted := DecryptWithContext(encrypted, key, []byte("bravo"))

	t.Log("we did not panic on encryption")
	if bytes.Equal(decrypted, plaintext) {
		t.Error("but the output is incorrect")
	}
}

func TestContextImprintIsDeteministic(t *testing.T) {
	plaintext := []byte("secret message")
	key := NewSymmetricKey()
	encrypted1 := EncryptWithContext(plaintext, key, []byte("same"))
	encrypted2 := EncryptWithContext(plaintext, key, []byte("same"))
	encrypted3 := EncryptWithContext(plaintext, key, []byte("not quite"))

	if !bytes.Equal(encrypted1, encrypted2) {
		t.Error("encryption with same parameters produces same result")
	}

	if bytes.Equal(encrypted2, encrypted3) {
		t.Error("but with different context the result is different")
	}
}

func TestDecryptWithContextFromSimulator(t *testing.T) {
	// These values were obtained from Themis interactive simulator:
	// https://docs.cossacklabs.com/simulator/data-cell/
	authenticationToken := []byte("secret key")
	contextVerification := []byte("Themis Simulator")
	expectedMessage := []byte("encrypted message")
	encryptedTextBase64 := "7HbjuD8Lc7OCHlxHnV+G8+o="
	encryptedText, _ := base64.StdEncoding.DecodeString(encryptedTextBase64)

	plaintext := DecryptWithContext(encryptedText, authenticationToken, contextVerification)

	if !bytes.Equal(plaintext, expectedMessage) {
		t.Error("decryption should succeed for data from simulator")
	}
}
