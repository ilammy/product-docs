package cell

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestTokenProtectMode(t *testing.T) {
	plaintext := []byte("secret message")
	key := NewSymmetricKey()
	ciphertext, token := EncryptToken(plaintext, key, nil)
	decrypted := DecryptToken(ciphertext, token, key, nil)

	if len(ciphertext) != len(plaintext) {
		t.Error("encrypted data must preserve length")
	}
	if len(token) == 0 {
		t.Error("however, there's non-empty token to take care of")
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data must be equal to plaintext")
	}
}

func TestTokenProtectIsLikeSealMode(t *testing.T) {
	plaintext := []byte("secret message")
	key := NewSymmetricKey()
	ciphertext, token := EncryptToken(plaintext, key, nil)
	decrypted := Decrypt(append(token, ciphertext...), key, nil)

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("if you append ciphertext to token, you get Seal mode")
	}
}

func TestDecryptTokenFromSimulator(t *testing.T) {
	// These values were obtained from Themis interactive simulator:
	// https://docs.cossacklabs.com/simulator/data-cell/
	authenticationToken := []byte("secret key")
	contextVerification := []byte("Themis Simulator")
	expectedMessage := []byte("encrypted message")
	autheticationDataChunkBase64 := "AAEBQAwAAAAQAAAAEQAAAF1J3zo0uXBRkzSuJcpunTN7bTxA8J/qZ9GrXyQ="
	autheticationDataChunk, _ := base64.StdEncoding.DecodeString(autheticationDataChunkBase64)
	encryptedTextBase64 := "kLVLbloC5vjIC0sxoIAJlU0="
	encryptedText, _ := base64.StdEncoding.DecodeString(encryptedTextBase64)

	plaintext := DecryptToken(encryptedText, autheticationDataChunk, authenticationToken, contextVerification)

	if !bytes.Equal(plaintext, expectedMessage) {
		t.Error("decryption should succeed for data from simulator")
	}
}
