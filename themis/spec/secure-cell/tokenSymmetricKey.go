package cell

import (
	"../common"
)

// SymmetricKeyToken is used by Secure Cell with symmetric keys.
type SymmetricKeyToken struct {
	AlgorithmID   common.AlgorithmID
	IV            []byte
	AuthTag       []byte
	MessageLength int
}

// Serialize the token and append it to the provided slice which is then returned.
func (token *SymmetricKeyToken) Serialize(buffer []byte) []byte {
	buffer = appendU32LE(buffer, uint32(token.AlgorithmID))
	buffer = appendU32LE(buffer, uint32(len(token.IV)))
	buffer = appendU32LE(buffer, uint32(len(token.AuthTag)))
	buffer = appendU32LE(buffer, uint32(token.MessageLength))
	buffer = append(buffer, token.IV...)
	buffer = append(buffer, token.AuthTag...)
	return buffer
}

// ParseSymmetricKeyToken extracts the token from the buffer and returns it
// along with the remaining part of the slice.
func ParseSymmetricKeyToken(buffer []byte) (*SymmetricKeyToken, []byte) {
	buffer, algorithmID := readU32LE(buffer)
	buffer, ivLength := readU32LE(buffer)
	buffer, authTagLength := readU32LE(buffer)
	buffer, messageLength := readU32LE(buffer)
	buffer, iv := readBytes(buffer, int(ivLength))
	buffer, authTag := readBytes(buffer, int(authTagLength))
	return &SymmetricKeyToken{
		AlgorithmID:   common.AlgorithmID(algorithmID),
		IV:            iv,
		AuthTag:       authTag,
		MessageLength: int(messageLength),
	}, buffer
}
