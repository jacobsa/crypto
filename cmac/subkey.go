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

package cmac

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/jacobsa/aes/common"
)

var subkeyZero []byte
var subkeyRb []byte

func init() {
	subkeyZero = bytes.Repeat([]byte{0x00}, 16)
	subkeyRb = append(bytes.Repeat([]byte{0x00}, 15), 0x87)
}

// Given a 128-bit key, generateSubkey returns two subkeys that can be used in
// MAC generation and verification. This is the Generate_Subkey function of RFC
// 4493.
func generateSubkey(key []byte) (k1 []byte, k2 []byte) {
	if len(key) != 16 {
		panic("generateSubkey requires a 16-byte key.")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("aes.NewCipher: %v", err))
	}

	l := make([]byte, 16)
	c.Encrypt(l, subkeyZero)

	if common.Msb(l) == 0 {
		k1 = shiftLeft(l)
	} else {
		k1 = common.Xor(shiftLeft(l), subkeyRb)
	}

	if common.Msb(k1) == 0 {
		k2 = shiftLeft(k1)
	} else {
		k2 = common.Xor(shiftLeft(k1), subkeyRb)
	}

	return
}
