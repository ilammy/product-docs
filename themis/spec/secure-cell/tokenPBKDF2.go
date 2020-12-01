package cell

import (
	"../common"
)

// PBKDF2Token is used by Secure Cell with passphrases.
type PBKDF2Token struct {
	AlgorithmID   common.AlgorithmID
	IV            []byte
	AuthTag       []byte
	MessageLength int
	KDFIterations int
	KDFSalt       []byte
}

// Serialize the token and append it to the provided slice which is then returned.
func (token *PBKDF2Token) Serialize(buffer []byte) []byte {
	buffer = appendU32LE(buffer, uint32(token.AlgorithmID))
	buffer = appendU32LE(buffer, uint32(len(token.IV)))
	buffer = appendU32LE(buffer, uint32(len(token.AuthTag)))
	buffer = appendU32LE(buffer, uint32(token.MessageLength))
	kdfContextLength := 4 + 2 + len(token.KDFSalt)
	buffer = appendU32LE(buffer, uint32(kdfContextLength))
	buffer = append(buffer, token.IV...)
	buffer = append(buffer, token.AuthTag...)
	buffer = appendU32LE(buffer, uint32(token.KDFIterations))
	buffer = appendU16LE(buffer, uint16(len(token.KDFSalt)))
	buffer = append(buffer, token.KDFSalt...)
	return buffer
}

// ParsePBKDF2Token extracts the token from the buffer and returns it
// along with the remaining part of the slice.
func ParsePBKDF2Token(buffer []byte) (*PBKDF2Token, []byte) {
	buffer, algorithmID := readU32LE(buffer)
	buffer, ivLength := readU32LE(buffer)
	buffer, authTagLength := readU32LE(buffer)
	buffer, messageLength := readU32LE(buffer)
	buffer, _ = readU32LE(buffer) // kdfContextLength not verified
	buffer, iv := readBytes(buffer, int(ivLength))
	buffer, authTag := readBytes(buffer, int(authTagLength))
	buffer, kdfIterations := readU32LE(buffer)
	buffer, kdfSaltLength := readU16LE(buffer)
	buffer, kdfSalt := readBytes(buffer, int(kdfSaltLength))
	return &PBKDF2Token{
		AlgorithmID:   common.AlgorithmID(algorithmID),
		IV:            iv,
		AuthTag:       authTag,
		MessageLength: int(messageLength),
		KDFIterations: int(kdfIterations),
		KDFSalt:       kdfSalt,
	}, buffer
}
