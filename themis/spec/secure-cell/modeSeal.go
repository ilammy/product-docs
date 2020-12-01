package cell

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"

	"../common"
)

var algorithmAES256GCM = common.MakeAlgorithmID(
	common.AesGCM,
	common.NoKDF,
	common.PKCS7Padding, // due to historical reasons, actually no padding
	/* key bits: */ 256,
)

// Encrypt plaintext with Secure Cell in Seal mode using symmetric key.
// The context is optional and can be nil.
func Encrypt(plaintext, symmetricKey, context []byte) []byte {
	encryptionKey := deriveKey(len(plaintext), symmetricKey, context)
	iv := generateNewIV()
	ciphertext, authTag := encryptGCM(encryptionKey, iv, plaintext, context)
	authToken := SymmetricKeyToken{
		AlgorithmID:   algorithmAES256GCM,
		IV:            iv,
		AuthTag:       authTag,
		MessageLength: len(ciphertext),
	}
	buffer := make([]byte, 0, len(ciphertext))
	return append(authToken.Serialize(buffer), ciphertext...)
}

// Decrypt data encrypted by Secure Cell in Seal mode using symmetric key.
// The context must match the one used during encryption.
func Decrypt(sealedCell, symmetricKey, context []byte) []byte {
	authToken, ciphertext := ParseSymmetricKeyToken(sealedCell)
	if authToken.AlgorithmID != algorithmAES256GCM {
		panic("algorithm not supported")
	}
	if authToken.MessageLength != len(ciphertext) {
		panic("malformed Secure Cell")
	}
	encryptionKey := deriveKey(len(ciphertext), symmetricKey, context)
	plaintext, err := decryptGCM(encryptionKey, authToken.IV, ciphertext, authToken.AuthTag, context)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

const aesKeyLength = 32
const kdfLabel = "Themis secure cell message key"

func deriveKey(plaintextLength int, symmetricKey, context []byte) []byte {
	lengthContext := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthContext, uint32(plaintextLength))
	return common.SoterKDF(symmetricKey, kdfLabel, aesKeyLength, lengthContext, context)
}

const ivLength = 12

func generateNewIV() []byte {
	iv := make([]byte, ivLength)
	_, err := rand.Read(iv)
	if err != nil {
		panic(err.Error())
	}
	return iv
}

func encryptGCM(encryptionKey, iv, plaintext, context []byte) (ciphertext []byte, authTag []byte) {
	aes, _ := aes.NewCipher(encryptionKey)
	aead, _ := cipher.NewGCM(aes)
	combined := aead.Seal(nil, iv, plaintext, context)
	ciphertext = combined[:len(combined)-aead.Overhead()]
	authTag = combined[len(combined)-aead.Overhead():]
	return ciphertext, authTag
}

func decryptGCM(encryptionKey, iv, ciphertext, authTag, context []byte) ([]byte, error) {
	aes, _ := aes.NewCipher(encryptionKey)
	aead, _ := cipher.NewGCM(aes)
	combined := make([]byte, 0, len(ciphertext)+len(authTag))
	combined = append(combined, ciphertext...)
	combined = append(combined, authTag...)
	return aead.Open(nil, iv, combined, context)
}
