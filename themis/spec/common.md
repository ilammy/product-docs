---
weight: 90
title:  Common data structures
---

# Common data structures

## Soter container

**Soter container** is used by many cryptosystems as an envelope for data.
It is a relatively lightweight container providing basic integrity checks.

### Data layout

Layout of a Soter container looks like this:

     0       4       8       12
    +-------+-------+-------+---------------------------------------+
    |  tag  |  size |  crc  |                payload                |
    +-------+-------+-------+---------------------------------------+

where

  - **tag** (4 bytes) is an identification code, akin to FourCC
  - **size** (4 bytes) stores the size of the container in bytes
  - **crc** (4 bytes) is a checksum of the container

All fields are stored in big-endian (network) byte order.

The **tag** field provides identification of the data stored in the Soter container.
It can be an arbitrary 4-byte sequence, but Soter and Themis prefer readable ASCII codes.
For example, here are some of the codes in use:

  - `UEC2` and `REC2` – EC keys on the P-256 elliptic curve
  - `TSPM` – Secure Session protocol messages
  - `TSSC` – serialized Secure Session state

The maximum size of a Soter container is limited to 4 GB,
due to the size of the **size** field.
Specifically, the maximum size of Soter container **payload** is 4,294,967,284 bytes.
Note that the **size** field includes both the header (12 bytes) and the payload.

The **crc** field is computed as reflected Castagnoli CRC-32C with polynomial 0x11EDC6F41,
as defined by [RFC 3309](https://tools.ietf.org/html/rfc3309) for SCTP.
The checksum is computed for the entire Soter container,
including the header in which the **crc** field is assumed to be zero.

### Integrity guarantees

Soter container provides only weak integrity guarantees.
CRC is enough to detect random bit flips and accidental data corruption in most cases,
but it provides no protection against malicious tampering and no error correction.

Thus, Soter containers are used in Themis for data which does not have other, cryptographic integrity checks embedded into it.
Most prominently, [asymmetric keys](../asymmetric-keypairs/) are enclosed in Soter containers.

### Example

Example container data (a public key):

```
00000000  55 45 43 32 00 00 00 2d  6c d5 6e f8 03 a4 b1 f7  |UEC2...-l.n.....|
00000010  28 43 ca 03 61 e1 81 1b  d0 b4 a1 2d 9a c4 81 3a  |(C..a......-...:|
00000020  2c 60 5d b2 45 51 b8 a4  71 a8 69 ae 8d           |,`].EQ..q.i..|
```

where you can see the data fields:

| Field   | Offset | Data          | Meaning |
| ------- | ------ | ------------- | ------- |
| tag     | 0x00   | `55 45 43 32` | `UEC2` – EC public key for the P-256 curve |
| size    | 0x04   | `00 00 00 2D` | 45 bytes: 12 bytes of header, 33 bytes of payload |
| crc     | 0x08   | `6C D5 6E F8` | container checksum |
| payload | 0x0C   | `03 A4 B1...` | data payload: public key parameters |

Here is a code snippet in Go, illustrating computation of Soter container checksum:

```go
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"hash/crc32"
)

func main() {
	containerB64 := "VUVDMgAAAC1s1W74A6Sx9yhDygNh4YEb0LShLZrEgTosYF2yRVG4pHGoaa6N"
	container, _ := base64.StdEncoding.DecodeString(containerB64)

	crc := crc32.New(crc32.MakeTable(crc32.Castagnoli))

	// First write then "tag" and "size" fields, then a zero placeholder
	// for the "crc" field, and finally the payload.
	crc.Write(container[0:8])
	crc.Write(make([]byte, 4))
	crc.Write(container[12:])

	checksum := crc.Sum(nil)

	// Soter uses *reflected* Castagnoli CRC.
	checksum[0], checksum[3] = checksum[3], checksum[0]
	checksum[1], checksum[2] = checksum[2], checksum[1]

	if bytes.Equal(checksum, container[8:12]) {
		fmt.Println("✅ container checksum")
	} else {
		fmt.Println("❌ container checksum")
	}
}
```

## Soter symmetric algorithm descriptor

**Soter algorithm descriptor** is used by some cryptosystems to identify symmetric encryption algorithms.
While in most cases it is used internally in API,
some cryptosystems actually store corresponding descriptors with encrypted data.

Algorithm descriptors are 32-bit bitmasks with multiple fields:

          28      24      20      16      12       8       4       0
    +-------+-------+-------+-------+-------+-------+-------+-------+
    |  alg. |  KDF  |  ---  |padding|  ---  |      key length       |
    +-------+-------+-------+-------+-------+-------+-------+-------+

where

  - **algorithm** (4 bits) defines the encryption algorithm
  - **KDF** (4 bits) identifies built-in key derivation function
  - **padding** (4 bits) defines padding in use, if any
  - **key length** (12 bits) stores the symmetric key length

Some of the bits are currently unused and reserved.
They are always set to zero.

Supported values for the **algorithm** are:

  - `0x1` — AES-ECB (_deprecated_)
  - `0x2` — AES-CTR
  - `0x3` — AES-XTS
  - `0x4` — AES-GCM

**KDF** choices are as follows:

  - `0x0` — Soter KDF (or no KDF, depending on context)
  - `0x1` — PBKDF2 with HMAC-SHA-256

Supported **padding** options are:

  - `0x0` — no padding
  - `0x1` — PKCS#7 padding

Available **key lengths** are:

  - `0x080` — 128 bits
  - `0x0C0` — 192 bits
  - `0x100` — 256 bits

### Example

Soter algorithm descriptors are most commonly found in [Secure Cells](../secure-cell/#layout)
where the most common options are AES-GCM variants.
For example: `0x40010100`, where you can see the data fields:

| Field      | Offset | Data            | Meaning        |
| ---------- | ------:| --------------- | -------------- |
| algorithm  |     28 | `4` (4 bits)    | AES-GCM        |
| KDF        |     24 | `0` (4 bits)    | Soter KDF      |
| *reserved* |     20 | `0` (4 bits)    | —              |
| padding    |     16 | `1` (4 bits)    | PKCS#7 padding |
| *reserved* |     12 | `0` (4 bits)    | —              |
| key length |      0 | `100` (12 bits) | 256-bit key    |

## Soter KDF

**Soter KDF** is a key derivation function used by Themis in symmetric cryptosystems
to derive encryption keys from user-provided key material.

KDF enables secure usage of symmetric keys of arbitrary length,
regardless of the technical requirements of particular encryption algorithms.
It also reduces effective key reuse by incorporating additional context data into derived keys.

{{< hint info >}}
However, note that Soter KDF still requires strong keys as input.
It is also **not suitable for passphases**.
Themis makes use of alternative KDFs (such as PBKDF2)
in contexts where encryption keys need to be derived from passphrases.
{{< /hint >}}

Soter KDF is similar in construction to ZRTP KDF
defined by [RFC 6189](https://tools.ietf.org/html/rfc6189#section-4.5.1), section 4.5.1.

_KDF_(**KI**, **Label**, **Context**..., **L**) = _truncate_(_HMAC-SHA-256_(**KI**, 0x00000001 || **Label** || 0x00 || **Context**...), **L**)

where the inputs are

  - **KI** is the input symmetric key provided by the user
  - **Label** indicates purpose of key derivation, a byte string
  - **Context** is a list of additional “context data” bytes,
    such as a nonce pertaining to this particular derivation
  - **L** is the length of derived key in bytes

The input key **KI** is used to key the HMAC function (HMAC-SHA-256 in case of Soter KDF),
and the rest of the parameters are concatenated (||) and hashed by HMAC.
The output is truncated to the desired length **L**.

{{< hint info >}}
It is not possible to derive keys longer than the HMAC output.
That is 32 bytes in case of HMAC-SHA-256 used by Soter KDF.
{{< /hint >}}

The key differences between ZRTP KDF and Soter KDF algorithms are:

  - the input key **KI** may be omitted,
    in which case it is derived from **Label** and **Contexts**
  - the counter **i** has fixed value of 0x00000001
  - the **Context** data is a list, not a single byte string
  - the length **L** is not included into the hashed string

If the input key **KI** is not provided by the user,
an _implicit key_ **KI′** is derived in the following manner:

**KI′** = _truncate_(**Label**, 32) ⊕ _truncate_(**Context**, 32) ⊕ ⋯

The implicit key is 32 bytes long.
If the **Label** or any of the **Contexts** is longer, they are truncated to 32 bytes,
and if they are shorter, they are padded with zeros before being added up with XOR (⊕).

### Example

Here is a code snippet in Go, illustrating computation of Soter KDF:

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func SoterKDF(input []byte, label string, context [][]byte, output []byte) {
	// Respect limitations of HMAC-SHA-256.
	if len(output) < 1 || len(output) > 32 {
		panic("invalid output length")
	}
	// Derive implicit key if necessary.
	if len(input) == 0 {
		input = make([]byte, 32)
		xor(input, []byte(label))
		for _, context := range context {
			xor(input, context)
		}
	}
	// Derive output key.
	mac := hmac.New(sha256.New, input)
	mac.Write([]byte{0x00, 0x00, 0x00, 0x01})
	mac.Write([]byte(label))
	mac.Write([]byte{0x00})
	for _, context := range context {
		mac.Write(context)
	}
	result := mac.Sum(nil)
	// Return the truncated result.
	copy(output, result[:len(output)])
}

func xor(out, in []byte) {
	L := len(out)
	if len(in) < L {
		L = len(in)
	}
	for i := 0; i < L; i++ {
		out[i] = out[i] ^ in[i]
	}
}

func main() {
	inputKey, _ := hex.DecodeString(
		"4e6f68365577616568696564316b696a6f74686168326f506f68306565517565",
	)
	label := "Example key derivation"
	context := [][]byte{[]byte("2020-12-20"), []byte("11:18:24")}

	output := make([]byte, 32)

	// With explicit input key:
	// d5f5be45fd6eab6dcbf93c21c3d2d1e3e888fa20ef38f2f4a121c196382342dd
	SoterKDF(inputKey, label, context, output)
	fmt.Println(hex.EncodeToString(output))

	// With implicit input key:
	// cf9846b8026c5b76a0641aa85f4152ff02c15ad45b726c6e578be52afdfd6930
	SoterKDF(nil, label, context, output)
	fmt.Println(hex.EncodeToString(output))
}
```
