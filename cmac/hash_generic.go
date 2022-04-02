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

// +build riscv64

// This code doesn't require that it's safe to perform unaligned word-sized loads, but has a poor performance.

package cmac

import (
	"unsafe"
)

// XOR the blockSize bytes starting at a and b, writing the result over dst.
func xorBlock(
	dstPtr unsafe.Pointer,
	aPtr unsafe.Pointer,
	bPtr unsafe.Pointer) {
	// Convert.
	a := (*[blockSize]byte)(aPtr)
	b := (*[blockSize]byte)(bPtr)
	dst := (*[blockSize]byte)(dstPtr)

	// Compute.
	for i := 0; i < blockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}
