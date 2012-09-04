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
	"fmt"
)

// Given a key and plaintext, encrypt the plaintext using the SIV mode of AES,
// as defined by RFC 5297, and return the result (including both the synthetic
// initialization vector and the ciphertext). The output can later be fed to
// Decrypt to recover the plaintext.
//
// In addition to confidentiality, this function also offers authenticity. That
// is, without the secret key, and attacker is unable to construct a byte
// string that Decrypt will accept.
//
// The supplied associated data, up to 126 strings, may also be authenticated,
// though it is not included in the ciphertext. The user must supply the same
// associated data to Decrypt in order for the latter to succeed. If no
// associated data is desired, pass nil or an empty slice.
//
// If the same key, plaintext, and associated data are supplied to this
// function multiple times, the output is guaranteed to be identical.
func Encrypt(key, plaintext []byte, associated [][]byte) ([]byte, error) {
	return nil, fmt.Errorf("TODO")
}

