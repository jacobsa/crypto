// Copyright 2012 Aaron Jacobs. All Rights Reserved.
// Author: aaronjjacobs@gmail.com (Aaron Jacobs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func dup(d []byte) []byte {
	result := make([]byte, len(d))
	copy(result, d)
	return result
}

// Given a key and plaintext, encrypt the plaintext using the SIV mode of AES,
// as defined by RFC 5297, append the result (including both the synthetic
// initialization vector and the ciphertext) to dst, and return the updated
// slice. The output can later be fed to Decrypt to recover the plaintext.
//
// In addition to confidentiality, this function also offers authenticity. That
// is, without the secret key an attacker is unable to construct a byte string
// that Decrypt will accept.
//
// The supplied key must be 32, 48, or 64 bytes long.
//
// The supplied associated data, up to 126 strings, is also authenticated,
// though it is not included in the ciphertext. The user must supply the same
// associated data to Decrypt in order for the Decrypt call to succeed. If no
// associated data is desired, pass an empty slice.
//
// If the same key, plaintext, and associated data are supplied to this
// function multiple times, the output is guaranteed to be identical. As per
// RFC 5297 section 3, you may use this function for nonce-based authenticated
// encryption by passing a nonce as the last associated data element.
func Encrypt(dst, key, plaintext []byte, associated [][]byte) ([]byte, error) {
	keyLen := len(key)
	associatedLen := len(associated)

	// Make sure the key length is legal.
	switch keyLen {
	case 32, 48, 64:
	default:
		return nil, fmt.Errorf("SIV requires a 32-, 48-, or 64-byte key.")
	}

	// Make sure the number of associated data is legal, per RFC 5297 section 7.
	if associatedLen > 126 {
		return nil, fmt.Errorf("len(associated) may be no more than 126.")
	}

	// Derive subkeys.
	k1 := key[:keyLen/2]
	k2 := key[keyLen/2:]

	// Call S2V to derive the synthetic initialization vector.
	s2vStrings := make([][]byte, associatedLen+1)
	copy(s2vStrings, associated)
	s2vStrings[associatedLen] = plaintext

	v := s2v(k1, s2vStrings)
	if len(v) != aes.BlockSize {
		panic(fmt.Sprintf("Unexpected vector: %v", v))
	}

	// Create a CTR cipher using a version of v with the 31st and 63rd bits
	// zeroed out.
	q := dup(v)
	q[aes.BlockSize-4] &= 0x7f
	q[aes.BlockSize-8] &= 0x7f

	ciph, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %v", err)
	}

	ctrCiph := cipher.NewCTR(ciph, q)

	// Ensure the destination is large enough.
	lenDstBefore := len(dst)
	{
		needed := lenDstBefore + len(v) + len(plaintext)
		if cap(dst) < needed {
			tmp := make([]byte, lenDstBefore, needed+needed/4)
			copy(tmp, dst)
			dst = tmp
		}

		dst = dst[:needed]
	}

	// Copy in the SIV then fill in the ciphertext.
	copy(dst[lenDstBefore:], v)
	ctrCiph.XORKeyStream(dst[lenDstBefore+len(v):], plaintext)

	return dst, nil
}
