package cell

import (
	"crypto/aes"
	"crypto/cipher"

	"../common"
)

// EncryptWithContext encrypts plaintext with Secure Cell in Context Imprint mode using symmetric key.
// The context must be non-empty.
func EncryptWithContext(plaintext, symmetricKey, context []byte) []byte {
	if len(context) == 0 {
		panic("context must be non-empty (and preferably unique)")
	}
	// Note how "context" is used and how IV is generated for Context Imprint.
	// In contrast to Seal and Token Protect mode, the context is *not used*
	// for key derivation (but plaintext length still is). Furthermore, the IV
	// is derived deterministically--from the user-provided context and key.
	encryptionKey := deriveKey(len(plaintext), symmetricKey, nil)
	iv := deriveIV(encryptionKey, context)
	return encryptCTR(encryptionKey, iv, plaintext)
}

// DecryptWithContext encrypts plaintext with Secure Cell in Context Imprint mode using symmetric key.
// The context must be non-empty.
func DecryptWithContext(ciphertext, symmetricKey, context []byte) []byte {
	// AES-CTR is a XOR stream cipher, decryption is encryption applied again.
	// Note the lack of *any* correctness checking here: if you inputs are not
	// the same as they were during encryption -- well, you get garbage output.
	return EncryptWithContext(ciphertext, symmetricKey, context)
}

const ctrIVLength = 16
const ivLabel = "Themis secure cell message iv"

func deriveIV(encryptionKey, context []byte) []byte {
	return common.SoterKDF(encryptionKey, ivLabel, ctrIVLength, context)
}

func encryptCTR(encryptionKey, iv, plaintext []byte) []byte {
	aes, _ := aes.NewCipher(encryptionKey)
	ctr := cipher.NewCTR(aes, iv)
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}
