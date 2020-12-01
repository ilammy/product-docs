package cell

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestSealMode(t *testing.T) {
	plaintext := []byte("secret message")
	key := NewSymmetricKey()
	encrypted := Encrypt(plaintext, key, nil)
	decrypted := Decrypt(encrypted, key, nil)

	if len(encrypted) <= len(plaintext) {
		t.Error("encrypted data must be longer than plaintext")
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data must be equal to plaintext")
	}
}

func TestSealModeRandomess(t *testing.T) {
	plaintext := []byte("secret message")
	key := NewSymmetricKey()
	encrypted1 := Encrypt(plaintext, key, nil)
	encrypted2 := Encrypt(plaintext, key, nil)

	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("each encryption produces distinct result")
	}
}

func TestDecryptFromSimulator(t *testing.T) {
	// These values were obtained from Themis interactive simulator:
	// https://docs.cossacklabs.com/simulator/data-cell/
	authenticationToken := []byte("secret key")
	contextVerification := []byte("Themis Simulator")
	expectedMessage := []byte("encrypted message")
	encryptedTextBase64 := "AAEBQAwAAAAQAAAAEQAAAOMERFXGxo9o5Hvo2CcJcbss7FVtw30nrASSVLaREdtjjtxU5DyN16jGLEoUPA=="
	encryptedText, _ := base64.StdEncoding.DecodeString(encryptedTextBase64)

	plaintext := Decrypt(encryptedText, authenticationToken, contextVerification)

	if !bytes.Equal(plaintext, expectedMessage) {
		t.Error("decryption should succeed for data from simulator")
	}
}
