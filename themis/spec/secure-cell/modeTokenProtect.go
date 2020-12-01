package cell

// EncryptToken encrypts plaintext with Secure Cell in Token Protect mode using symmetric key.
// The context is optional and can be nil.
// Ciphertext and authentication token are returned separately.
func EncryptToken(plaintext, symmetricKey, context []byte) (ciphertext []byte, token []byte) {
	encryptionKey := deriveKey(len(plaintext), symmetricKey, context)
	iv := generateNewIV()
	ciphertext, authTag := encryptGCM(encryptionKey, iv, plaintext, context)
	authToken := SymmetricKeyToken{
		AlgorithmID:   algorithmAES256GCM,
		IV:            iv,
		AuthTag:       authTag,
		MessageLength: len(ciphertext),
	}
	return ciphertext, authToken.Serialize(nil)
}

// DecryptToken validates authentication token and decrypts data
// encrypted by Secure Cell in Token Protect mode using symmetric key.
// The context must match the one used during encryption.
func DecryptToken(ciphertext, token, symmetricKey, context []byte) []byte {
	authToken, remaining := ParseSymmetricKeyToken(token)
	if len(remaining) != 0 {
		panic("malformed Secure Cell token")
	}
	if authToken.AlgorithmID != algorithmAES256GCM {
		panic("algorithm not supported")
	}
	if authToken.MessageLength != len(ciphertext) {
		panic("malformed Secure Cell token")
	}
	encryptionKey := deriveKey(len(ciphertext), symmetricKey, context)
	plaintext, err := decryptGCM(encryptionKey, authToken.IV, ciphertext, authToken.AuthTag, context)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}
