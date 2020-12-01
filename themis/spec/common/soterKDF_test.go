package common

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const label = "Example key derivation"

func TestExplicitKey(t *testing.T) {
	inputKey, _ := hex.DecodeString(
		"4e6f68365577616568696564316b696a6f74686168326f506f68306565517565",
	)
	expectedOutput, _ := hex.DecodeString(
		"d5f5be45fd6eab6dcbf93c21c3d2d1e3e888fa20ef38f2f4a121c196382342dd",
	)
	output := SoterKDF(inputKey, label, 32, []byte("2020-12-20"), []byte("11:18:24"))

	if !bytes.Equal(output, expectedOutput) {
		t.Logf("expected: %s", hex.EncodeToString(expectedOutput))
		t.Logf("actual:   %s", hex.EncodeToString(output))
		t.Error("invalid Soter KDF output")
	}
}

func TestImplicitKey(t *testing.T) {
	expectedOutput, _ := hex.DecodeString(
		"cf9846b8026c5b76a0641aa85f4152ff02c15ad45b726c6e578be52afdfd6930",
	)
	output := SoterKDF(nil, label, 32, []byte("2020-12-20"), []byte("11:18:24"))

	if !bytes.Equal(output, expectedOutput) {
		t.Logf("expected: %s", hex.EncodeToString(expectedOutput))
		t.Logf("actual:   %s", hex.EncodeToString(output))
		t.Error("invalid Soter KDF output")
	}
}
