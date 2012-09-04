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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/jacobsa/aes/common"
	"hash"
)

type cmacHash struct {
	// An AES cipher configured with the original key.
	ciph cipher.Block

	// Generated sub-keys.
	k1 []byte
	k2 []byte

	// Data that has been seen since the last block was disposed of (i.e. since
	// we finished an iteration of the for loop in RFC 4493's AES-CMAC algorithm
	// and were sure we were going into a new one).
	data []byte

	// The current value of X, as defined in the AES-CMAC algorithm in RFC 4493.
	// Initially this is a 128-bit zero, and it is updated with the current block
	// when we're sure it's not the last one.
	x []byte
}

func (h *cmacHash) Write(p []byte) (n int, err error) {
	// Consume the data.
	n = len(p)
	h.data = append(h.data, p...)

	// Consume any blocks that we're sure aren't the last.
	blocksToProcess := len(h.data) / 16
	if blocksToProcess > 0 && len(h.data)%16 == 0 {
		blocksToProcess--
	}

	for i := 0; i < blocksToProcess; i++ {
		block := h.data[16*i : 16*(i+1)]
		y := common.Xor(h.x, block)
		h.ciph.Encrypt(h.x, y)
	}

	h.data = h.data[16*blocksToProcess:]

	return
}

func (h *cmacHash) Sum(b []byte) []byte {
	dataLen := len(h.data)

	// We should have at most one block left.
	if dataLen > 16 {
		panic(fmt.Sprintf("Unexpected data: %x", h.data))
	}

	// Calculate M_last.
	var mLast []byte
	if dataLen == 16 {
		mLast = common.Xor(h.data, h.k1)
	} else {
		mLast = common.Xor(common.PadBlock(h.data), h.k2)
	}

	y := common.Xor(mLast, h.x)
	result := make([]byte, 16)
	h.ciph.Encrypt(result, y)

	b = append(b, result...)
	return b
}

func (h *cmacHash) Reset() {
	h.data = []byte{}
	h.x = make([]byte, 16)
}

func (h *cmacHash) Size() int {
	return 16
}

func (h *cmacHash) BlockSize() int {
	return 16
}

// New returns a CMAC hash using the supplied key, which must be 16 bytes long.
func New(key []byte) (hash.Hash, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES-CMAC requires a 16-byte key.")
	}

	// Create a cipher.
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %v", err)
	}

	// Set up the hash object.
	h := &cmacHash{ciph: ciph}
	h.k1, h.k2 = generateSubkeys(ciph)
	h.Reset()

	return h, nil
}
