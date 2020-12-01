package common

// AlgorithmID encodes symmetric algorithm parameters for Soter.
type AlgorithmID uint32

const (
	algorithmMask   = 0xF0000000
	algorithmOffset = 28
	kdfMask         = 0x0F000000
	kdfOffset       = 24
	paddingMask     = 0x000F0000
	paddingOffset   = 16
	keyLengthMask   = 0x00000FFF
	keyLengthOffset = 0
)

// MakeAlgorithmID constructs algorithm ID from components.
func MakeAlgorithmID(algorithm SymmetricAlgorithm, kdf KeyDerivationFunction, padding PaddingAlgorithm, keyBits int) AlgorithmID {
	var value uint32
	value |= (uint32(algorithm) & (algorithmMask >> algorithmOffset)) << algorithmOffset
	value |= (uint32(kdf) & (kdfMask >> kdfOffset)) << kdfOffset
	value |= (uint32(padding) & (paddingMask >> paddingOffset)) << paddingOffset
	value |= (uint32(keyBits) & (keyLengthMask >> keyLengthOffset)) << keyLengthOffset
	return AlgorithmID(value)
}

// SymmetricAlgorithm indicates symmetric encryption algorithm in AlgorithmID.
type SymmetricAlgorithm int

// Supported SymmetricAlgorithm values.
const (
	AesECB SymmetricAlgorithm = iota + 1
	AesCBC
	AesXTS
	AesGCM
)

// Algorithm returns symmetric algorithm component.
func (id AlgorithmID) Algorithm() SymmetricAlgorithm {
	return SymmetricAlgorithm((id & algorithmMask) >> algorithmOffset)
}

// KeyDerivationFunction indicates key derivation function in AlgorithmID.
type KeyDerivationFunction int

// Supported KeyDerivationFunction values.
const (
	NoKDF KeyDerivationFunction = iota
	PBKDF2HmacSha256
)

// KDF returns key derivation function.
func (id AlgorithmID) KDF() KeyDerivationFunction {
	return KeyDerivationFunction((id & kdfMask) >> kdfOffset)
}

// PaddingAlgorithm indicates padding algorithm in AlgorithmID.
type PaddingAlgorithm int

// Supported PaddingAlgorithm values.
const (
	NoPadding PaddingAlgorithm = iota
	PKCS7Padding
)

// Padding returns padding algorithm.
func (id AlgorithmID) Padding() PaddingAlgorithm {
	return PaddingAlgorithm((id & paddingMask) >> paddingOffset)
}

// KeyBits returns size of the key in bits.
func (id AlgorithmID) KeyBits() int {
	return int((id & keyLengthMask) >> keyLengthOffset)
}
