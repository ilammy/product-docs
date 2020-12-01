package cell

import (
	"encoding/binary"
)

func appendU32LE(buffer []byte, value uint32) []byte {
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, value)
	return append(buffer, tmp...)
}

func appendU16LE(buffer []byte, value uint16) []byte {
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, value)
	return append(buffer, tmp...)
}

func readU32LE(buffer []byte) ([]byte, uint32) {
	return buffer[4:], binary.LittleEndian.Uint32(buffer[:4])
}

func readU16LE(buffer []byte) ([]byte, uint16) {
	return buffer[2:], binary.LittleEndian.Uint16(buffer[:2])
}

func readBytes(buffer []byte, n int) ([]byte, []byte) {
	return buffer[n:], buffer[:n]
}
