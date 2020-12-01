---
weight: 10
title:  Secure Cell
---

# Secure Cell

{{< hint info >}}
This part of Themis documentation is currently under development.
Please come back later.

Meanwhile, you can [read an overview of the Secure Cell cryptosystem](/themis/crypto-theory/cryptosystems/secure-cell/).
{{< /hint >}}

**Secure Сell** is a high-level cryptographic container
aimed at protecting arbitrary data stored in various types of storages
(e.g., databases, filesystem files, document archives, cloud storage, etc.).
You can read [Secure Cell overview](/themis/crypto-theory/cryptosystems/secure-cell/)
to get a high-level picture of the cryptosystem.

At its core, Secure Cell is based around AES encryption algorithm
in Galois/Counter Mode (GCM) providing authenticated encryption capabilities.
It also supports regular Counter Mode (CTR) if ciphertext length needs to be preserved.
The rest of the cryptosystem ensures that AES is used in a secure way.

## Desired and designed properties

First of all, let's discuss the desired properties of the cryptosystem.

  - Strong confidentiality and integrity guarantees.

    Given the typical use cases for Secure Cell,
    it must prevent direct and indirect disclosure of protected data
    in addition to preventing inadvertent modifications to it.

    Secure Cell uses proven authenticated encryption schemes
    to provide integrity and confidentiality guarantees.

  - Good performance for both encryption and decryption.

    Given the typical use cases for Secure Cell,
    it is important for it to be as fast as possible while being secure.

    Secure Cell uses well-known symmetric encryption algorithms
    for which hardware acceleration is generally available.

Now let's talk about some *non-goals* which influence design decisions.

  - Data pieces are protected individually.

    Secure Cell is designed to operate on individual data pieces,
    such as database fields, encryption keys, etc.

    Each protected piece of data is independent of any other.
    Secure Cell does not provide nor enforce any ordering between them.

    Contrast this with [Secure Session](../secure-session/) cryptosystem
    which protects ordered streams of packets, similar to TLS.

  - Symmetric encryption scheme is used.

    Secure Cell uses the same shared secret key to both encrypt and decrypt data.
    This is a symmetric encryption scheme.

    In contrast, [Secure Message](../secure-message/) cryptosystem is asymmetric,
    which is more practical for authenticated message exchange between distinct parties.

  - Data payload has bounded size.

    While the size of Secure Cell payload is not *strictly* limited,
    it is still expected to be bounded.
    That is, Secure Cell is not designed for handling data streams of arbitrary length,
    nor does it provide random access into data within an encrypted cell.

Finally, let's consider the desired cryptography-theoretical properties of the cryptosystem.
Secure Cell is required to be at least IND-CPA secure
and it would be nice to achieve IND-CCA2 whenever possible.
The choice of AES-GCM and AES-CTR satisfies these requirements.
Here are some examples of vulnerabilities mitigated by Secure Cell:

  - Optional context data prevents malicious reuse of ciphertexts in different contexts.
    Mismatches will be detected and reported.

  - Even in case of extremely short inputs, no information about plaintext is disclosed.
    For example, you can use Secure Cell to secure a boolean field in the database.

  - It is not possible for the attacker to restore the encryption secret
    even if they can exploit the system to encrypt arbitrary data
    or trick it into decrypting some known encrypted data.

## Operation modes

Secure Cell can operate in multiple modes which can be split on several axes:

  - authenticated encryption or just confidentiality
  - whether auxiliary data is detached or embedded
  - whether associated data is used or not
  - whether the secret is a key or a passphrase

{{< hint info >}}
Some of the combinations are excluded for security and technical reasons.
For example, if no authentication is provided then you cannot use passphrases and must use associated data.
{{< /hint >}}

Ultimately, Secure Cell supports the following major modes:

  - **Seal** mode with optional associated data, secured by a key or a passphrase.
  - **Token Protect** mode with optional associated data, secured by a key.
  - **Context Imprint** mode with required associated data, secured by a key.

Now let's dissect these variations in more detail.

### Authenticated encryption

On one axis, Secure Cell can either provide *authentication* or not:

  - **Authenticated encryption** provides strong integrity guarantees.

    That is, on decryption you can be sure that the data has not been tampered with.
    Encrypted message is secure from prying eyes and idle hands.

  - **Unauthenticated encryption** provides only confidentiality guarantees.

    That is, while the attacker cannot read the encrypted message (as with any encryption),
    they can still easily corrupt or modify it without you being able to undeniably confirm it.

**Seal** and **Token Protect** modes use authenticated encryption
while **Context Imprint** mode is not authenticated.

Secure Cell provides authentication via AES-GCM encryption mode
and unauthenticated encryption via the regular AES-CTR mode.

The tradeoff here is that AES-GCM produces an *authentication tag*
which needs to be stored with encrypted data, increasing its length.
Sometimes it is acceptable, in other cases you may not have that flexibility.

Seal and Token Protect are basically the same,
but Token Protect mode stores the authentication tag and other auxiliary data in a detached buffer.
This allows to replace the original message with an encrypted one of the same length,
if you can afford to store the auxiliary data elsewhere.

Context Imprint mode exists for use cases which do not allow for any additional storage.
This constraint somewhat lowers the security of the cryptosystem
since there is no space for authentication data or – more importantly – random IV.
To compensate for this, Secure Cell requires *associated data* to be used in Context Imprint mode.

### Associated data and nonces

Another axis of Secure Cell is how much *associated data* the user provides for encryption.

**Associated data** is used in encryption algorithm, influencing its output,
but it is not a part of the plaintext, the ciphertext, or the encryption key.

Associated data provides another layer of protection against unintended disclosure, use, and modification of encrypted data.
Different associated data makes the same plaintext with the same key to be encrypted into a different ciphertext.
This makes it much harder for the attacker to guess the content of encrypted messages.
It also makes it harder to reuse encrypted data verbatim in different contexts (replay attacks).

Some parts of the associated data can be transmitted together with the ciphertext, but some can be omitted.
This complicates unintended decryption: even if the attacker has obtained the encryption key somehow,
they still need to get ahold of the associated data which might be stored elsewhere (like the user's brain).

A related concept is **nonce** – an arbitrary random number which must be used only once in cryptographic communication.
The AES-GCM and AES-CTR algorithms used by Secure Cell use an *initialisation vector* (IV) as a nonce.
Since they are effectively streaming ciphers, it is **critical** for security to never reuse nonces:
the most powerful known attack on AES-GCM is based on IV reuse.
Secure Cell includes several mitigations for it.

With Secure Cell, in addition to the message and the key, users can provide extra **context data**
which is used to derive associated data for encryption.
If the context data is not provided explicitly, Secure Cell derives some from the message length.
It is also used in key derivation to minimise the risks of key reuse and XOR attacks as well.
See the [Encryption](#encryption) section for the details.

**Seal** and **Token Protect** modes require additional storage for authentication data.
Therefore, Secure Cell can use a bit more of that extra storage
to choose and keep a completely new, random IV for each encrypted piece of data.
Thus, user-provided context is optional in Seal and Token Protect modes
but it can still be provided to enhance security even further.

On the other hand, **Context Imprint** mode must preserve the length of the input.
It does not allow for any unaccounted randomess and thus is completely deterministic:
given the same input, key, and context, the resulting output is always the same.
In Context Imprint mode the IV is derived from available encryption key and context data,
making the encryption susceptible to nonce reuse attacks.
This is the reason why in Context Imprint mode the users are *required* to provide context data,
and encouraged to use unique context data for each encryption to maintain security.

### Keys vs. passphrases

Secure Cell supports several types of secrets used to secure encrypted data:

  - [Symmetric keys](../symmetric-keys/) for machines to remember.

    Keys should be as random as possible and can be as long as necessary.

  - [Passphrases](../symmetric-keys/#passphrases) for humans to remember.

    Since human memory is usually not good at remembering strings of random numbers,
    passphrases are typically shorter and have fewer randomness per character.

Ultimately, AES-256 encryption algorithm works with 256-bit keys.
Secure Cell uses _key derivation functions_ (KDF) to stretch or shrink user-provided keys to the length required by AES.
If a passphrase is used, a [special _passphrase_ KDF](/themis/crypto-theory/cryptosystems/secure-cell.md#key-derivation-functions) is employed
to compensate for potentially poorer statistical properties of passphrases.
See the [Encryption](#encryption) section for the details.

Passphrase KDFs require additional parameters which need to be adjusted with time, as computers get faster.
KDF parameters need to be stored together with the encrypted data so that it can always be decrypted.
Therefore, **Context Imprint** mode does not support passphrases as it has no spare space for the parameters.
Requiring the users to supply KDF parameters goes against Themis design philosophy.

Moreover, passphrase KDFs are designed to be exceedingly slow.
**Token Protect** mode is particularly useful in database contexts to encrypt individual database cells.
This use case is pretty sensitive to performance so *key wrapping* should be preferred.
As a result, only **Seal** mode provides passphrase support.

Finally, KDF plays another auxiliary role.
AES-GCM algorithm has a limit on how much data can be safely encrypted using the same key,
before cryptanalysis attacks become practical.
KDF mixes in user-provided associated data into the derived key,
randomising it, and reducing effective key reuse even when the same secret is used with Secure Cell.

## Layout

The two main parts of a Secure Cell are:

  - **encrypted data** which is self-explanatory, and
  - **authentication token** which keeps all auxiliary metadata

Their arrangement is defined by Secure Cell operation mode.

In Seal mode the authentication token is a header of a unified data block:

    +---------------------------------------------------------------+
    |                             token                             |
    +---------------------------------------------------------------+
    |                                                               |
    +                         encrypted data                        +
    |                                                               |
    +---------------------------------------------------------------+

In Token Protect mode the token is detached from encrypted data:

    +---------------------------------------------------------------+
    |                                                               |
    +                         encrypted data                        +
    |                                                               |
    +---------------------------------------------------------------+

    +---------------------------------------------------------------+
    |                             token                             |
    +---------------------------------------------------------------+

And in Context Imprint mode there is no authentication token at all:

    +---------------------------------------------------------------+
    |                                                               |
    +                         encrypted data                        +
    |                                                               |
    +---------------------------------------------------------------+

### Authentication token: symmetric keys

Layout of the authentication token depends on the type of secret in use.
For symmetric keys the token looks like this:

     0               4               8               12              16
    +---------------+---------------+---------------+---------------+
    |  algorithm ID |   IV length   |auth tag length| message length|
    +---------------+---------------+---------------+---------------+
    |                    IV data                    |    auth tag   >
    +---------------+---------------+---------------+---------------+
    >                auth tag (cont.)               |
    +---------------+---------------+---------------+

where

  - **algorithm ID** (4 bytes) describes the encryption algorithm
  - **IV length** (4 bytes) stores the length of **IV data** in bytes, normally 12
  - **auth tag length** (4 bytes) stores the length of **auth tag** in bytes, normally 16
  - **message length** (4 bytes) stores the length of **encrypted data** in bytes
  - **IV data** (12 bytes) stores the random initialisation vector for encryption
  - **auth tag** (16 bytes) stores integrity authentication tag produced by encryption

All non-data fields are stored in *little-endian* byte order.
**IV data** and **auth tag** are interpreted as is.

{{< hint info >}}
Contrary to most other data structures in Themis,
Secure Cell uses little-endian due to historical reasons.
{{< /hint >}}

The **algorithm ID** field is actually a bitmask with
[Soter symmetric algorithm descriptor](../common/#soter-symmetric-algorithm-descriptor):

          28      24      20      16      12       8       4       0
    +-------+-------+-------+-------+-------+-------+-------+-------+
    |  alg. |  KDF  |  ---  |padding|  ---  |      key length       |
    +-------+-------+-------+-------+-------+-------+-------+-------+

As of Themis 0.13 released in 2020,
Secure Cell in Seal and Token Protect mode uses AES-GCM, with Soter KDF, and PKCS#7 padding.
This results in the following descriptors currently being in use for symmetric keys:

| Encryption algorithm       | Algorithm ID |
| -------------------------- | ------------ |
| AES-256-GCM **(default)**  | `0x40010100` |
| AES-192-GCM                | `0x400100C0` |
| AES-128-GCM (_deprecated_) | `0x40010080` |

Refer to the [algorithm descriptor overview](../common/#soter-symmetric-algorithm-descriptor) for details.

The **IV data** and **auth tag** fields are theoretically flexible,
but with current algorithm choice IV is always 12 bytes long
and authentication tag takes 16 bytes.
These values are consistent with recommendations of [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
for use with AES-GCM algorithm.

The **message length** field limits the maximum length of Secure Cell encrypted data to 4 GB.
(Authentication token length is not counted against this limit.)

### Authentication token: passphrases

When Secure Cell is used with passphrases
the authentication token contains an additional block with *passphrase key derivation context*.
In this case the layout of the token is as follows:

     0               4               8               12              16
    +---------------+---------------+---------------+---------------+
    |  algorithm ID |   IV length   |auth tag length| message length|
    +---------------+---------------+---------------+---------------+
    |   KDF length  |                    IV data                    |
    +---------------+---------------+---------------+---------------+
    |                           auth tag                            |
    +---------------+---------------+---------------+---------------+
    |                       KDF context data                        |
    +               +       +-------+---------------+---------------+
    |                       |
    +---------------+-------+

where

  - **algorithm ID** (4 bytes) describes the encryption algorithm
  - **IV length** (4 bytes) stores the length of **IV data** in bytes, normally 12
  - **auth tag length** (4 bytes) stores the length of **auth tag** in bytes, normally 16
  - **message length** (4 bytes) stores the length of **encrypted data** in bytes
  - **KDF length** (4 bytes) stores the length of **KDF context data** in bytes
  - **IV data** (12 bytes) stores the random initialisation vector for encryption
  - **auth tag** (16 bytes) stores integrity authentication tag produced by encryption
  - **KDF context data** (22 bytes) stores passphrase KDF parameters

Most fields have the same meaning as with symmetric keys, and use *little-endian* byte order.

As of Themis 0.13 released in 2020,
Secure Cell in Seal mode uses AES-GCM, with PBKDF2 over HMAC-SHA-256, and PKCS#7 padding.
This results in the following **algorithm ID** values currently being in use for passphrases:

| Encryption algorithm       | Algorithm ID |
| -------------------------- | ------------ |
| AES-256-GCM **(default)**  | `0x41010100` |
| AES-192-GCM                | `0x410100C0` |
| AES-128-GCM (_deprecated_) | `0x41010080` |

Refer to the [algorithm descriptor overview](../common/#soter-symmetric-algorithm-descriptor) for details.

The PBKDF2 passphrase key derivation uses the following KDF context format:

     0               4       6                                       16
    +---------------+-------+-------+---------------+---------------+
    |   iterations  |salt l.|                  salt                 >
    +---------------+-------+-------+---------------+---------------+
    >      salt (cont.)     |
    +---------------+-------+

where

  - **iterations** (4 bytes) is the number of PBKDF2 iterations to perform
  - **salt length** (2 bytes) stores the length of **salt** in bytes
  - **salt** (16 bytes) stores the random salt for key derivation

The **iteration** count is stored as is.
Currently, Secure Cell uses 200,000 iterations by default.
This value is stored as `40 0d 03 00` in little-endian encoding.

The **salt** field is theoretically flexible,
but with current algorithm choice the salt is always 16 bytes long.
These values are consistent with recommendations of [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final)
for use with PBKDF2 password-based key derivation algorithm.

## Example

Now let's look at and dissect sample data protected by Secure Cell.
You can try it out yourself using [command-line utilities](/themis/debugging/cli-utilities/) if you have Themis installed,
or with [Themis Server](/themis/debugging/themis-server/) from your web browser.

### Example: symmetric keys

With the following inputs
for [the `scell_seal_string_echo` utility](/themis/debugging/cli-utilities/):

| Input          | Value |
| -------------- | ----- |
| encryption key | `au6aimoa8Pee8wahxi4Aique6eaxai2a` |
| plaintext      | `encrypted message` |
| context data   | `additional context` |

Secure Cell in Seal mode produces the following output (encoded in base64):

    AAEBQAwAAAAQAAAAEQAAAM5da3KkReYC7++OPbrI13UycoVi3s01Ji64WQ/KIe+3oF8cgLle19WC+tnaCg==

which looks like this in hexadecimal (61 bytes):

```
00000000  00 01 01 40 0c 00 00 00  10 00 00 00 11 00 00 00  |...@............|
00000010  ce 5d 6b 72 a4 45 e6 02  ef ef 8e 3d ba c8 d7 75  |.]kr.E.....=...u|
00000020  32 72 85 62 de cd 35 26  2e b8 59 0f ca 21 ef b7  |2r.b..5&..Y..!..|
00000030  a0 5f 1c 80 b9 5e d7 d5  82 fa d9 da 0a           |._...^.......|
```

There you can note the authentication token (44 bytes):

```
00000000  00 01 01 40 0c 00 00 00  10 00 00 00 11 00 00 00  |...@............|
00000010  ce 5d 6b 72 a4 45 e6 02  ef ef 8e 3d ba c8 d7 75  |.]kr.E.....=...u|
00000020  32 72 85 62 de cd 35 26  2e b8 59 0f -- -- -- --  |2r.b..5&..Y.    |
00000030  -- -- -- -- -- -- -- --  -- -- -- --              |             |
```

and the actual encrypted data (17 bytes) in the end:

```
00000000  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000010  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000020  -- -- -- -- -- -- -- --  -- -- -- -- ca 21 ef b7  |            .!..|
00000030  a0 5f 1c 80 b9 5e d7 d5  82 fa d9 da 0a           |._...^.......|
```

Since Seal mode has been used, the token and data are concatenated.
In Token Protect mode they would have been returned as separate buffers.
Here's how they look encoded in base64:

    AAEBQAwAAAAQAAAAEQAAAM5da3KkReYC7++OPbrI13UycoVi3s01Ji64WQ8=

    yiHvt6BfHIC5XtfVgvrZ2go=

Try decrypting this data in Token Protect mode, it should work!

Let's inspect the authentication token now.
Match [the reference](#authentication-token--symmetric-keys)
with the data as follows:

| Field           | Offset | Data          | Meaning |
| --------------- | ------ | ------------- | ------- |
| algorithm ID    | 0x00   | `00 01 01 40` | `0x40010100` – AES-GCM-256, Soter KDF, PKCS#7 padding |
| IV length       | 0x04   | `0c 00 00 00` | IV data is 12 bytes long |
| auth tag length | 0x08   | `10 00 00 00` | auth tag is 16 bytes long |
| message length  | 0x0C   | `11 00 00 00` | payload is 17 bytes long |
| IV data         | 0x10   | `ce . . . 3d` | initialisation vector data |
| auth tag        | 0x1C   | `ba . . . 0f` | authentication tag data |

All the encoded values match the expectations.

### Example: passphrases

With the following inputs
for [the `scell_seal_string_echo_pw` utility](/themis/debugging/cli-utilities/):

| Input        | Value |
| ------------ | ----- |
| passphrase   | `correct horse battery staple` |
| plaintext    | `encrypted message` |
| context data | `additional context` |

Secure Cell in Seal mode produces the following output (encoded in base64):

    AAEBQQwAAAAQAAAAEQAAABYAAACM/x16YGKwIuBTawsFRQGgiBsJjuw8nHwShTmmQA0DABAA1a5WowtWsVhDAh/ZChtv+NKLyNk7N4KUsEd+6wvDl5rO

which looks like this in hexadecimal (87 bytes):

```
00000000  00 01 01 41 0c 00 00 00  10 00 00 00 11 00 00 00  |...A............|
00000010  16 00 00 00 8c ff 1d 7a  60 62 b0 22 e0 53 6b 0b  |.......z`b.".Sk.|
00000020  05 45 01 a0 88 1b 09 8e  ec 3c 9c 7c 12 85 39 a6  |.E.......<.|..9.|
00000030  40 0d 03 00 10 00 d5 ae  56 a3 0b 56 b1 58 43 02  |@.......V..V.XC.|
00000040  1f d9 0a 1b 6f f8 d2 8b  c8 d9 3b 37 82 94 b0 47  |....o.....;7...G|
00000050  7e eb 0b c3 97 9a ce                              |~......|
```

There you can note the extended authentication token (48 bytes):

```
00000000  00 01 01 41 0c 00 00 00  10 00 00 00 11 00 00 00  |...A............|
00000010  16 00 00 00 8c ff 1d 7a  60 62 b0 22 e0 53 6b 0b  |.......z`b.".Sk.|
00000020  05 45 01 a0 88 1b 09 8e  ec 3c 9c 7c 12 85 39 a6  |.E.......<.|..9.|
00000030  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000040  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000050  -- -- -- -- -- -- --                              |       |
```

the passphase key derivation context (22 bytes):

```
00000000  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000010  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000020  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000030  40 0d 03 00 10 00 d5 ae  56 a3 0b 56 b1 58 43 02  |@.......V..V.XC.|
00000040  1f d9 0a 1b 6f f8 -- --  -- -- -- -- -- -- -- --  |....o.          |
00000050  -- -- -- -- -- -- --                              |       |
```

and the actual encrypted data (17 bytes) in the end:

```
00000000  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000010  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000020  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000030  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  |                |
00000040  -- -- -- -- -- -- d2 8b  c8 d9 3b 37 82 94 b0 47  |      ....;7...G|
00000050  7e eb 0b c3 97 9a ce                              |~......|
```

Secure Cell supports passphrases only in Seal mode,
therefore the authentication token cannot be detached from the encrypted data.

Let's inspect the authentication token now.
Match [the reference](#authentication-token--passphrases)
with the data as follows:

| Field           | Offset | Data          | Meaning |
| --------------- | ------ | ------------- | ------- |
| algorithm ID    | 0x00   | `00 01 01 41` | `0x41010100` – AES-GCM-256, PBKDF2, PKCS#7 padding |
| IV length       | 0x04   | `0c 00 00 00` | IV data is 12 bytes long |
| auth tag length | 0x08   | `10 00 00 00` | auth tag is 16 bytes long |
| message length  | 0x0C   | `11 00 00 00` | payload is 17 bytes long |
| KDF length      | 0x10   | `16 00 00 00` | KDF context is 22 bytes long |
| IV data         | 0x14   | `8c . . . 0b` | initialisation vector data |
| auth tag        | 0x20   | `05 . . . a6` | authentication tag data |

and the PBKDF context data is interpreted like this:

| Field           | Offset | Data          | Meaning |
| --------------- | ------ | ------------- | ------- |
| iteration count | 0x30   | `40 0d 03 00` | 200,000 iterations |
| salt length     | 0x34   | `10 00`       | salt is 16 bytes long |
| salt            | 0x36   | `d5 . . . f8` | salt data |

All the encoded values match the expectations.

### Example: Context Imprint mode

With the following inputs
for [the `scell_context_string_echo` utility](/themis/debugging/cli-utilities/):

| Input          | Value |
| -------------- | ----- |
| encryption key | `au6aimoa8Pee8wahxi4Aique6eaxai2a` |
| plaintext      | `encrypted message` |
| context data   | `additional context` |

Secure Cell in Context Imprint mode produces the following output (encoded in base64):

    egHLD0020cqhs5uB93CqdNA=

which looks like this in hexadecimal (17 bytes):

```
00000000  7a 01 cb 0f 4d 36 d1 ca  a1 b3 9b 81 f7 70 aa 74  |z...M6.......p.t|
00000010  d0                                                |.|
```

Note that the output has exactly the same length as the original plaintext.
It also never changes on repeated encryption,
contrary to the behaviour of other modes
which always produce a slightly different output each time with the same input parameters.

### Reference implementation

```go
// AlgorithmID in its parsed form.
type AlgorithmID struct {
        Algorithm SymmetricAlgorithm
        KDF       KeyDerivationFunction
        Padding   PaddingAlgorithm
        KeyBits   int
}

// SymmetricAlgorithm supported by Themis.
type SymmetricAlgorithm int

const (
        AESECB SymmetricAlgorithm = iota + 1
        AESCBC
        AESXTS
        AESGCM
)

// KeyDerivationFunction supported by Themis.
type KeyDerivationFunction int

const (
        NoKDF KeyDerivationFunction = iota
        PBKDF2HMACSHA256
)

// PaddingAlgorithm supported by Themis.
type PaddingAlgorithm int

const (
        NoPadding PaddingAlgorithm = iota
        PKCS7Padding
)

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

func (id AlgorithmID) AsUint32() uint32 {
        var value uint32
        value |= (uint32(id.Algorithm) & (algorithmMask >> algorithmOffset)) << algorithmOffset
        value |= (uint32(id.KDF) & (kdfMask >> kdfOffset)) << kdfOffset
        value |= (uint32(id.Padding) & (paddingMask >> paddingOffset)) << paddingOffset
        value |= (uint32(id.KeyBits) & (keyLengthMask >> keyLengthOffset)) << keyLengthOffset
        return value
}

func ParseAlgorithmID(value uint32) AlgorithmID {
        return AlgorithmID{
                Algorithm: SymmetricAlgorithm((value & algorithmMask) >> algorithmOffset),
                KDF:       KeyDerivationFunction((value & kdfMask) >> kdfOffset),
                Padding:   PaddingAlgorithm((value & paddingMask) >> paddingOffset),
                KeyBits:   int((value & keyLengthMask) >> keyLengthOffset),
        }
}
```

<!---->

```go
// SymmetricKeyToken is used by Secure Cell with symmetric keys.
type SymmetricKeyToken struct {
        AlgorithmID   AlgorithmID
        IV            []byte
        AuthTag       []byte
        MessageLength int
}

// Serialize the token and append it to the provided slice which is then returned.
func (token *SymmetricKeyToken) Serialize(buffer []byte) []byte {
        buffer = append(buffer, putUint32LE(token.AlgorithmID.AsUint32()))
        buffer = append(buffer, putUint32LE(uint32(len(token.IV))))
        buffer = append(buffer, putUint32LE(uint32(len(token.AuthTag))))
        buffer = append(buffer, putUint32LE(uint32(token.MessageLength)))
        buffer = append(buffer, token.IV)
        buffer = append(buffer, token.AuthTag)
        return buffer
}

// ParseSymmetricKeyToken extracts the token from the buffer and returns it
// along with the remaining part of the slice.
func ParseSymmetricKeyToken(buffer []byte) (*SymmetricKeyToken, []byte) {
        buffer, algorithmID := getUint32LE(buffer)
        buffer, ivLength := getUint32LE(buffer)
        buffer, authTagLength := getUint32LE(buffer)
        buffer, messageLength := getUint32LE(buffer)
        buffer, iv := buffer[int(ivLength):], buffer[:int(ivLength)]
        buffer, authTag := buffer[int(authTagLength):], buffer[:int(authTagLength)]
        return &SymmetricKeyToken{
                AlgorithmID:   ParseAlgorithmID(algorithmID),
                IV:            iv,
                AuthTag:       authTag,
                MessageLength: int(messageLength),
        }, buffer
}
```

<!---->

```go
// PassphrasePBKDF2Token is used by Secure Cell with passphrases & PBKDF2.
type PassphrasePBKDF2Token struct {
        AlgorithmID   AlgorithmID
        IV            []byte
        AuthTag       []byte
        MessageLength int
        Iterations    int
        KDFSalt       []byte
}

// Serialize the token and append it to the provided slice which is then returned.
func (token *PassphrasePBKDF2Token) Serialize(buffer []byte) []byte {
        buffer = append(buffer, putUint32LE(token.AlgorithmID.AsUint32()))
        buffer = append(buffer, putUint32LE(uint32(len(token.IV))))
        buffer = append(buffer, putUint32LE(uint32(len(token.AuthTag))))
        buffer = append(buffer, putUint32LE(uint32(token.MessageLength)))
        buffer = append(buffer, putUint32LE(uint32(4 + 2 + len(token.KDFSalt)))
        buffer = append(buffer, token.IV)
        buffer = append(buffer, token.AuthTag)
        buffer = append(buffer, putUint32LE(uint32(token.Iterations)))
        buffer = append(buffer, putUint16LE(uint16(len(token.KDFSalt))))
        buffer = append(buffer, token.KDFSalt)
        return buffer
}

// ParsePassphrasePBKDF2Token extracts the token from the buffer and returns it
// along with the remaining part of the slice.
func ParsePassphrasePBKDF2Token(buffer []byte) (*PassphrasePBKDF2Token, []byte) {
        buffer, algorithmID := getUint32LE(buffer)
        buffer, ivLength := getUint32LE(buffer)
        buffer, authTagLength := getUint32LE(buffer)
        buffer, messageLength := getUint32LE(buffer)
        buffer, _ := getUint32LE(buffer) // KDF context length
        buffer, iv := getBytes(buffer, int(ivLength))
        buffer, authTag := getBytes(buffer, int(authTagLength))
        buffer, iterations := getUint32LE(buffer)
        buffer, saltLength := getUint16LE(buffer)
        buffer, salt := getBytes(buffer, int(saltLength))
        return &PassphrasePBKDF2Token{
                AlgorithmID:   ParseAlgorithmID(algorithmID),
                IV:            iv,
                AuthTag:       authTag,
                MessageLength: int(messageLength),
                Iterations:    int(iterations),
                KDFSalt:       salt,
        }, buffer
}
```

<!---->

```go
import "encoding/binary"

func putUint16LE(value uint16) []byte {
        bytes := make([]byte, 2)
        binary.LittleEndian.PutUint16(tmp, value)
        return bytes
}

func putUint32LE(value uint32) []byte {
        bytes := make([]byte, 4)
        binary.LittleEndian.PutUint32(tmp, value)
        return bytes
}

func getUint16LE(buffer []byte) ([]byte, uint16) {
        return buffer[2:], binary.LittleEndian.Uint16(buffer[:2])
}

func getUint32LE(buffer []byte) ([]byte, uint32) {
        return buffer[4:], binary.LittleEndian.Uint32(buffer[:4])
}

func getBytes(buffer []byte, length int) ([]byte, []byte) {
        return buffer[length:], buffer[:length]
}
```

## Encryption algorithm

Now, let's discuss how Secure Cell encryption algorithm works.
There are three inputs to it:

  - **plaintext** which needs to be encrypted
  - **secret** which secures the encryption, either a key or a passphrase
  - **context** data which will be associated with resulting Secure Cell

which are transformed into the following two outputs:

  - **ciphertext** of the same length as plaintext
  - **authentication token** with all auxiliary metadata

As noted before, each Secure Cell mode has its own specifics:

  - Seal and Token Protect modes allow the context to be empty.
  - Seal mode concatenates and returns ciphertext and token together.
  - Token Protect mode returns ciphertext and token separately.
  - Context Imprint mode does not produce any token at all.
  - Only Seal mode support passphrase secrets.

Also, the algorithm is slightly different depending on the type of secret in use.

### Encryption with symmetric keys

Seal and Token Protect mode have the following data flow
when used with symmetric keys:

```
  0. User input

+-------------+     +-------------+     +-------------+
|  Plaintext  |     |  Symm. key  |     |   Context   |
+-------------+     +-------------+     +-------------+
       |                   |                   |
       |                   |                   |
  1. Encryption key derivation                 |
       |                   |                   |
       |                   v                   |
       | (len only) ++-----------++            |
       +----------->|| Soter KDF ||<-----------+
       |            ++-----------++            |
       |                   |                   |
       |                   v  (kept in-memory) |
       |            +- - - - - - -+            |
       |            |   Enc. key  |            |
       |            +- - - - - - -+            |
       |                   |                   |
  2. Encryption            |                   |
       |                   |                   |
       v                   v                   |   /dev/urandom
  ++---------------------------++              |         |
  ||                           ||<-------------+         v
  ||          AES GCM          ||                 +-------------+
  ||                           ||<----------------|  Init. vec. |
  ++---------------------------++                 +-------------+
       |                   |                             |
       v                   v                             |
+-------------+     +-------------+                      |
|  Ciphertext |     |  Auth. tag  |                      |
+-------------+     +-------------+                      |
       |                   |                             |
       |                   |                             |
  3. Secure Cell assembly  |                             |
       |                   |                             |
       |                   v  (also algorithm params.)   |
       |          +------------------+                   |
       |          |  Authentication  |<------------------+
       |          |      token       |
       |          +------------------+
       |                   |
       v                   v
    +-------------------------+
    |       Secure Cell       |  (concatenated only in Seal mode)
    +-------------------------+
```

#### Encryption overview

Written concisely, Secure Cell encryption algorithm is as follows:

  **E** = _Soter-KDF_(**K**, **L**, [_length_(**P**), **A**], **N**)

  **IV** = _random_(12)

  **C**, **G** = _AES-GCM-encrypt_(**P**, **E**, **A**, **IV**)

  **T** = _make-tag_(**G**, **IV**, _length_(**C**), **N**)

  _Seal_ = **T** || **C**

  _Token-Protect_ = (**C**, **T**)

The inputs are symmetric key **K**, plaintext **P**, and associated context **A**.
An encryption key **E** is derived using inputs and algorithm constants **L** and **N**.
New initialisation vector **IV** is generated and used for encryption,
which produces ciphertext **C** and authentication tag **G**.
Public parameters and authentication data are assembled into authentication tag **T**
which is the ultimate output of Secure Cell, along with the ciphertext.

#### Detailed encryption steps

Secure Cell encryption algorithm can be divided into the following steps:

 1. **Key derivation** where user-provided symmetric key and context data
    are transformed into the actual *encryption key*.

    Secure Cell uses [Soter KDF](../common/#soter-kdf)
    – a ZRTP-style key derivation function –
    to derive encryption key **E** from symmetric key **K**, plaintext **P**,
    and associated context **A**:

      **E** = _Soter-KDF_(**K**, **L**, [_length_(**P**), **A**], **N**)

    where KDF label **L** is a string `Themis secure cell message key` encoded in ASCII,
    and **N** is the length of the key used by AES algoritm:

    | Encryption algorithm       | N, key length       |
    | -------------------------- | ------------------- |
    | AES-256-GCM **(default)**  | 32 bytes (256 bits) |
    | AES-192-GCM                | 24 bytes (192 bits) |
    | AES-128-GCM (_deprecated_) | 16 bytes (128 bits) |

    KDF context includes length of the plaintext **P** in bytes,
    encoded as 32-bit unsigned integer in little-endian byte order.
    It is followed by any associated context data **A** provided by the user.

 2. **Encryption** is performed next.

    For this step, a random initialisation vector **IV** is generated first
    using a cryptographically secure pseudorandom number generator (CSPRNG).

      **IV** = _random_(12)

    The length of IV – 12 bytes – is selected according to recommendations of
    [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final).

    The plaintext **P**, derived encryption key **E**, associated context data **A**,
    and initialisation vector **IV** are then passed to AES-GCM algorithm:

      **C**, **G** = _AES-GCM-encrypt_(**P**, **E**, **A**, **IV**)

    which produces two outputs: ciphertext **C** and authentication tag **G**.
    According to recommendations of [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final),
    the tag is used as is, without any truncation.
    With AES-GCM its length is always 16 bytes, regardless of the key length.

 3. Finally, **Secure Cell is assembled** from outputs and intermediate data.

    Generated initialisation vector **IV**, authentication tag **G**,
    length of the ciphertext **C**, and algorithm descriptor including **N**
    are all combined into authentication token **T**:

      **T** = _make-tag_(**G**, **IV**, _length_(**C**), **N**)

    (See the [Layout](#example--symmetric-keys) section for reference.)

    In Seal mode ciphertext **C** is appended to authentication token **T**
    and the combined result is the output of Secure Cell:

      _Seal_ = **T** || **C**

    In Token Protect mode authentication token **T** and ciphertext **C**
    are returned separately:

      _Token-Protect_ = (**C**, **T**)

    The user is then responsible for keeping them associated until decryption.

### Notes about symmetric keys

Soter KDF allows to accomodate user-provided symmetric keys of any length,
regardless of the actual AES variation used by Secure Cell,
which have strict key length requirements
(exactly 256 bits for AES-256-GCM, for example).

Also, note that the derived key is never stored anywhere persistently
and can be wiped from RAM as soon as encryption has been performed.
Such approach minimizes the time span for which the real key is available directly,
making it hard to [fish for AES keys in memory]().

Using key derivation also significantly decreases the chance of key reuse,
since all user input – plaintext, symmetric key, and associated context –
influences the derived key value.
Along with random IV generation,
this mitigates the so called [“forbidden attack”](...)
and has other minor benefits.

### Decryption with symmetric keys

Secure Cell decryption is performed similarly to encryption,
it is a symmetric cryptosystem after all.

```
  0. User input

+---------------------------------+     +-------------+     +-------------+
|           Secure Cell           |     |  Symm. key  |     |   Context   |
+---------------------------------+     +-------------+     +-------------+
        |                  |                   |                   |
        |                  |                   |                   |
  1. Parse and validate input                  |                   |
        |                  |                   |                   |
        |                  v                   |                   |
+---------------+   +-------------+            |                   |
|  Auth. token  |   |  Ciphertext |            |                   |
+---------------+   +-------------+            |                   |
        |                  |                   |                   |
        |                  |                   |                   |
  2. Encryption key derivation                 |                   |
        |                  |                   |                   |
        |                  |                   v                   |
        |                  | (len only) ++-----------++            |
        |                  +----------->|| Soter KDF ||<-----------+
        |                  |            ++-----------++            |
        |                  |                   |                   |
        |                  |                   v  (kept in-memory) |
        |                  |            +- - - - - - -+            |
        |                  |            |   Enc. key  |            |
        |                  |            +- - - - - - -+            |
        |                  |                   |                   |
  3. Decryption            |                   |                   |
        |                  |                   |                   |
        v                  v                   v                   |
+-------------+       ++---------------------------++              |
|  Auth. tag  |------>||                           ||              |
+-------------+       ||          AES GCM          ||<-------------+
|  Init. vec. |------>||                           ||
+-------------+       ++---------------------------++
                                     |
                                     v
                              +-------------+
                              |  Plaintext  |
                              +-------------+
```

#### Decryption overview

Written concisely, Secure Cell decryption algorithm is as follows:

  **IV**, **G**, **N** = _parse-tag_(**T**)

  **E** = _Soter-KDF_(**K**, **L**, [_length_(**C**), **A**], **N**)

  **P** = _AES-GCM-decrypt_(**C**, **E**, **A**, **IV**, **G**)

First, authentication token **T** is separated from ciphertext **C** and parsed into components:
initialisation vector **IV**, authentication tag **G**, and key length **N**.
An encryption key **E** is derived using inputs and algorithm constants **L** and **N**.
Decryption restores plaintext **P** and verifies authentication tag **G**.

#### Detailed decryption steps

Secure Cell decryption algorithm can be divided into the following steps:

 1. **Input parsing and validation**.

    First, in Seal mode the input data is separated into authentication token **T** and ciphertext **C**.
    The tag contains enough information to calculate its own length
    as well as to cross-check length of the ciphertext.
    (See the [Layout](#example--symmetric-keys) section for reference.)

      **IV**, **G**, **N** = _parse-tag_(**T**)

    Token Protect mode also checks that the length information in authentication token **T**
    is consistent with itself and the length of the ciphertext **C**.
    Otherwise, the token or the cell might have been corrupted.

 2. **Encryption key is derived** from input data.

    Provided symmetric key **K** and associated context **A**
    together with the length of ciphertext **C**
    are passed to [Soter KDF](../common/#soter-kdf):

      **E** = _Soter-KDF_(**K**, **L**, [_length_(**C**), **A**], **N**)

    The required length of the derived key **N**
    is retrieved from the algorithm information in authentication token **T**.

    KDF label **L** is constant string `Themis secure cell message key` encoded in ASCII.

    KDF context includes length of the ciphertext **P** in bytes,
    encoded as 32-bit unsigned integer in little-endian byte order.
    It is followed by any associated context data **A** provided by the user.

    The resulting derived key **E** will be the same one which was used for encryption.

 3. **Decryption** is performed after that.

    The ciphertext **C** and associated context data **A** are provided by the user.
    Initialisation vector **IV** has been retrieved from authentication token **T**.
    Together with derived encryption key **E** they are passed to AES-GCM algorithm:

      **P** = _AES-GCM-decrypt_(**C**, **E**, **A**, **IV**, **G**)

    which verifies authentication tag **G** and produces plaintext **P**
    if the tag matches the expected value.

### Example of symmetric

Here is a code snippet in Go,
illustrating Secure Cell encryption and decryption in the most commonly used mode:
Seal mode with 256-bit keys.

```go
var algorithmAES256GCM AlgorithmID = AlgorithmID{
        Algorithm: AESGCM,
        KDF:       NoKDF,
        Padding:   NoPadding,
        KeyBits:   256,
}

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
        return append(authToken.Serialize(buffer), ciphertext)
}

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

const ivLength = 12

func generateNewIV() []byte {
        iv := make([]byte, ivLength)
        _, err := rand.Read(iv)
        if err != nil {
                panic(err.Error())
        }
        return iv
}

const aesKeyLength = 32
const kdfLabel = "Themis secure cell message key"

func deriveKey(plaintextLength int, symmetricKey, context []byte) []byte {
        encryptionKey := make([]byte, aesKeyLength)
        kdfContext := [][]byte{make([]byte, 4), context}
        binary.LittleEndian.PutUint32(kdfContext[0], uint32(plaintextLength))
        SoterKDF(symmetricKey, kdfLabel, kdfContext, encryptionKey)
        return encryptionKey
}

// Copy-paste SoterKDF() definition so that example is self-sufficient?

import "crypto/aes"
import "crypto/cipher"

func encryptGCM(encryptionKey, iv, plaintext, context []byte) (ciphertext []byte, authTag []byte) {
        aead, _ := cipher.NewGCM(aes.NewCipher(encryptionKey))
        combined := aead.Seal(nil, iv, plaintext, context)
        ciphertext = combined[:len(combined) - aead.Overhead()]
        authTag = combined[len(combined) - aead.Overhead():]
        return ciphertext, authTag
}

func decryptGCM(encryptionKey, iv, ciphertext, authTag, context []byte) ([]byte, error) {
        aead, _ := cipher.NewGCM(aes.NewCipher(encryptionKey))
        combined := make([]byte, 0, len(ciphertext)+len(authTag))
        append(combined, ciphertext)
        append(combined, authTag)
        return aead.Open(nil, iv, combined, context)
}
```

Note that this example omits non-essential error checks for the sake of brevity
as well as assumes non-malformed input on decryption.
Production-grade implementation will be significantly more meticulous.

### Encryption with passphrases

Passphrases are supported only in Seal mode because of reasons.
<!-- TODO: explain or link to reasons -->
In order to accomodate slightly worse properties of the passphrases
Secure Cell includes an additional passphrase-based key derivation step,
but otherwise the code algorithm remains the same.

Here's data flow of Secure Cell encryption when used with passphrases:

```
  0. User input

+-------------+     +-------------+     +-------------+
|  Plaintext  |     |  Passphrase |     |   Context   |
+-------------+     +-------------+     +-------------+
       |                   |                   |
       |                   |                   |
  1. Prekey derivation     |                   |             /dev/urandom
       |                   |                   |                   |
       |                   v                   |                   v
       |            ++-----------++            |            +-------------+
       |            ||   PBKDF2  ||<------------------------|   KDF salt  |
       |            ++-----------++            |            +-------------+
       |                   |                   |                   |
       |                   v  (kept in-memory) |                   |
       |            +- - - - - - -+            |                   |
       |            |    Prekey   |            |                   |
       |            +- - - - - - -+            |                   |
       |                   |                   |                   |
       |                   |                   |                   |
  2. Encryption key derivation                 |                   |
       |                   |                   |                   |
       |                   v                   |                   |
       | (len only) ++-----------++            |                   |
       +----------->|| Soter KDF ||<-----------+                   |
       |            ++-----------++            |                   |
       |                   |                   |                   |
       |                   v  (kept in-memory) |                   |
       |            +- - - - - - -+            |                   |
       |            |   Enc. key  |            |                   |
       |            +- - - - - - -+            |                   |
       |                   |                   |                   |
  3. Encryption            |                   |                   |
       |                   |                   |                   |
       v                   v                   |   /dev/urandom    |
  ++---------------------------++              |         |         |
  ||                           ||<-------------+         v         |
  ||          AES GCM          ||                 +-------------+  |
  ||                           ||<----------------|  Init. vec. |  |
  ++---------------------------++                 +-------------+  |
       |                   |                             |         |
       v                   v                             |         |
+-------------+     +-------------+                      |         |
|  Ciphertext |     |  Auth. tag  |                      |         |
+-------------+     +-------------+                      |         |
       |                   |                             |         |
       |                   |                             |         |
  4. Secure Cell assembly  |                             |         |
       |                   |                             |         |
       |                   v  (also algorithm params.)   |         |
       |          +------------------+                   |         |
       |          |  Authentication  |<------------------+         |
       |          |      token       |<----------------------------+
       |          +------------------+
       |                   |
       v                   v
    +-------------------------+
    |       Secure Cell       |
    +-------------------------+
```

You can note that the only difference with the Seal mode <!-- TODO: link -->
is the addition of the “prekey derivation” step before actual key derivation.

Basically, passphrase support is tacked on top the basic Secure Cell algorithm.
Arguably this makes the second key derivation redundant
and a different KDF design might have avoided that.
However, this composite design makes it easier to ensure the security of the cryptosystem.
Plus, it provides some nice compatiblity properties,
allowing to decouple passphrase-based key derivation later on.

### Encryption in Context Imprint mode

Context Imprint mode supports only symmetric keys and has the following data flow:

```
  0. User input

+---------------------+     +---------------------+     +---------------------+
|      Plaintext      |     |    Symmetric key    |     |  Associated context |
+---------------------+     +---------------------+     +---------------------+
           |                           |                           |
           |                           |                           |
           |                           |                           |
           +-----------------------+   |                           |
           |                       |   |                           |
  1. Key derivation                v   v                           |
           |                +-+-----------------+-+                |
           |                | |    Soter KDF    | |                |
           |                +-+-----------------+-+                |
           |                           |                           |
           |                           v                           |
           |                +- - - - - - - - - - -+   key is kept in memory,
           |                |    Encryption key   |   never stored anywhere
           |                +- - - - - - - - - - -+                |
           |                           |                           |
           |                           |                           |
           |                           |                           |
           |                           +-----------------------+   |
           |                           |                       |   |
  2. IV derivation                     |                       v   v
           |                           |                +-+-----------------+-+
           |                           |                | |    Soter KDF    | |
           |                           |                +-+-----------------+-+
           |                           |   IV is kept in memory,   |
           |                           |   never stored anywhere   v
           |                           |                +- - - - - - - - - - -+
           |                           |                | Initialisation vec. |
           |                           |                +- - - - - - - - - - -+
           |                           |                           |
           +-----------------------+   |   +-----------------------+
                                   |   |   |
  2. Encryption                    v   v   v
                            +-+-----------------+-+
                            | |     AES CTR     | |
                            +-+-----------------+-+
                                       |
                                       v
                            +---------------------+
                            |      Ciphertext     |
                            +---------------------+
```

#### Encryption overview

Written concisely, Secure Cell encryption algorithm is as follows:

  **E** = _Soter-KDF_(**K**, **L**<sub>key</sub>, [_length_(**P**)], **N**<sub>key</sub>)

  **IV** = _Soter-KDF_(**E**, **L**<sub>IV</sub>, [**A**], **N**<sub>IV</sub>)

  **C** = _AES-CTR-encrypt_(**P**, **E**, **IV**)

The inputs are symmetric key **K**, plaintext **P**, and associated context **A**.
An encryption key **E** is derived from user inputs
and algorithm constants **L**<sub>key</sub> and **N**<sub>key</sub>.
An initialisation vector **IV** is also deterministically derived from inputs
and algorithm constants **L**<sub>IV</sub> and **N**<sub>IV</sub>.
Encryption is performed using AES-CTR algorithm which outputs ciphertext **C**
of the same length as plaintext **P**.

#### Detailed encryption steps

Secure Cell encryption algorithm can be divided into the following steps:

 1. **Key derivation** where user-provided symmetric key
    is transformed into the actual *encryption key*.

    Secure Cell uses [Soter KDF](../common/#soter-kdf)
    – a ZRTP-style key derivation function –
    to derive encryption key **E** from symmetric key **K** and plaintext **P**:

      **E** = _Soter-KDF_(**K**, **L**<sub>key</sub>, [_length_(**P**)], **N**<sub>key</sub>)

    where KDF label **L**<sub>key</sub> is a string `Themis secure cell message key` encoded in ASCII,
    and **N**<sub>key</sub> is the length of the key used by AES algoritm:

    | Encryption algorithm       | N, key length       |
    | -------------------------- | ------------------- |
    | AES-256-CTR **(default)**  | 32 bytes (256 bits) |
    | AES-192-CTR                | 24 bytes (192 bits) |
    | AES-128-CTR (_deprecated_) | 16 bytes (128 bits) |

    KDF context includes length of the plaintext **P** in bytes,
    encoded as 32-bit unsigned integer in little-endian byte order.
    It is followed by any associated context data **A** provided by the user.

    {{< hint info >}}
    **Note:**
    Context Imprint mode uses the same algorithm for encryption key derivation
    as in Seal and Token Protect modes,
    but **does not include** user-provided context into the encryption key.
    Instead, it is used for the initialisation vector.
    {{< /hint >}}

 2. Deterministically **derive initialisation vector**.

    While Seal and Token Protect mode generate a random initialisation vector (**IV**) for each encryption,
    Context Imprint mode derives **IV** from encryption key **E** and associated context **A**:

      **IV** = _Soter-KDF_(**E**, **L**<sub>IV</sub>, [**A**], **N**<sub>IV</sub>)

    where KDF label **L**<sub>IV</sub> is a string `Themis secure cell message iv` encoded in ASCII,
    and **N**<sub>IV</sub> is always 16 bytes (the length of AES block).
    <!-- TODO: Why 16 bytes? Are there any NIST recommendations on this? -->

    This ensures that IV can be restored on decryption from just user input.
    Randomess is inherited from user-provided associated context **A**
    which should be unique for each encryption to ensure the highest level of security.

 3. **Encryption** is performed next.

    The plaintext **P**, derived encryption key **E** and initialisation vector **IV**
    are then passed to AES-CTR algorithm:

      **C** = _AES-CTR-encrypt_(**P**, **E**, **IV**)

    which produces ciphertext **C**, the output of Secure Cell.

    Note that AES-CTR does not use associated context **A** directly.

### Notes about Context Imprint mode

Context Imprint mode is intended for a very narrow set of use cases where additional storage is not available.
This limitation somewhat lowers the security of Context Imprint mode in comparison with Seal and Token Imprint modes.

Secure Cell uses nonce values to mitigate some of the most potent attacks on the cryptosystem.
In Seal and Token Imprint modes Themis transparently generates secure nonce values and stores them along with other encryption parameters.
However, in Context Imprint mode there is no place to store them, so the user is responsible for providing (unique) nonce values as input.

While it is a good idea to use unique associated context values with Seal and Token Protect modes too,
this does not have a drastic effect on overall security of these modes.
That is because they already use unique initialisation vectors.

In contrast, for Context Imprint mode, the associated context is the only source of nonce –
associated data that must be used only once.
Therefore, it is **critical** to use a different context for each data piece encrypted with the same key.

The derivation algorithm makes sure that context reuse does not lead to _blatant_ vulnerabilities,
but it could still very much compromise all messages of the same length, for example.

Because of these constraints,
the design of Context Imprint API is different from other modes:

  - Associated context is required in Context Imprint mode.

    An empty value is the easiest one to be accidentally reused.
    Requiring a non-empty associated context makes the users think about what value would be appropriate.

  - Context Imprint mode supports only symmetric keys.

    Passphrases are not supported because passphrase KDF requires additional salt for security.
    However, Context Imprint mode does not provide a natural way to store it.

    While the users could be able to store the salt on encryption and provide it on decryption,
    such approach makes Secure Cell API impractical and unnecessarily complex.
    This contradicts Themis design philosophy.

    Given that Context Imprint mode is already a special-purpose mode,
    an option to use passphrases is not provided for it.

<!-- note the lack of verification -->

### Decryption in Context Imprint mode

Context Imprint decryption is almost the same as encryption,
it is a symmetric cryptosystem after all.

```
  0. User input

+---------------------+     +---------------------+     +---------------------+
|      Ciphertext     |     |    Symmetric key    |     |  Associated context |
+---------------------+     +---------------------+     +---------------------+
           |                           |                           |
           |                           |                           |
           |                           |                           |
           +-----------------------+   |                           |
           |                       |   |                           |
  1. Key derivation                v   v                           |
           |                +-+-----------------+-+                |
           |                | |    Soter KDF    | |                |
           |                +-+-----------------+-+                |
           |                           |                           |
           |                           v                           |
           |                +- - - - - - - - - - -+   key is kept in memory,
           |                |    Encryption key   |   never stored anywhere
           |                +- - - - - - - - - - -+                |
           |                           |                           |
           |                           |                           |
           |                           |                           |
           |                           +-----------------------+   |
           |                           |                       |   |
  2. IV derivation                     |                       v   v
           |                           |                +-+-----------------+-+
           |                           |                | |    Soter KDF    | |
           |                           |                +-+-----------------+-+
           |                           |   IV is kept in memory,   |
           |                           |   never stored anywhere   v
           |                           |                +- - - - - - - - - - -+
           |                           |                | Initialisation vec. |
           |                           |                +- - - - - - - - - - -+
           |                           |                           |
           +-----------------------+   |   +-----------------------+
                                   |   |   |
  2. Decryption                    v   v   v
                            +-+-----------------+-+
                            | |     AES CTR     | |
                            +-+-----------------+-+
                                       |
                                       v
                            +---------------------+
                            |      Plaintext      |
                            +---------------------+
```

#### Decryption overview

Written concisely, Secure Cell decryption algorithm is as follows:

  **E** = _Soter-KDF_(**K**, **L**<sub>key</sub>, [_length_(**C**)], **N**<sub>key</sub>)

  **IV** = _Soter-KDF_(**E**, **L**<sub>IV</sub>, [**A**], **N**<sub>IV</sub>)

  **P** = _AES-CTR-decrypt_(**C**, **E**, **IV**)

The inputs are symmetric key **K**, ciphertext **C**, and associated context **A**.
An encryption key **E** is derived from user inputs
and algorithm constants **L**<sub>key</sub> and **N**<sub>key</sub>.
An initialisation vector **IV** is also deterministically derived from inputs
and algorithm constants **L**<sub>IV</sub> and **N**<sub>IV</sub>.
With all of this, AES-CTR algorithm returns decrypted plaintext **P**.

Note that Secure Cell in Context Imprint mode has zero data overhead
and all inputs are provided directly, there is nothing to parse or verify.

#### Detailed decryption steps

Secure Cell decryption algorithm can be divided into the following steps:

 1. **Encryption key is derived** from input data.

    The algorithm is the same as for encryption, using Soter KDF to obtain encryption key **E**
    from symmetric key **K** and length of ciphertext **C**:

      **E** = _Soter-KDF_(**K**, **L**<sub>key</sub>, [_length_(**C**)], **N**<sub>key</sub>)

    Ciphertext has the same length as the plaintext,
    therefore the resulting derived key **E** will be the same one which was used for encryption.

 2. **Initialisation vector is derived** next in the same manner.

    Context Imprint mode does not store the **IV** value with encrypted message,
    it needs to be derived from input parameters before decryption:

      **IV** = _Soter-KDF_(**E**, **L**<sub>IV</sub>, [**A**], **N**<sub>IV</sub>)

    Given the same values as used for encryption, the resulting **IV** will come out the same.

 3. **Decryption** is performed next.

    The ciphertext **C**, derived encryption key **E** and initialisation vector **IV**
    are then passed to AES-CTR algorithm:

      **P** = _AES-CTR-decrypt_(**C**, **E**, **IV**)

    which produces plaintext **P**.

    Note that Context Imprint mode does not authenticate decrypted data.
    In case of incorrect of malformed inputs it returns garbage output with no indication.
