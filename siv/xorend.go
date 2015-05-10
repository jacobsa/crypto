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
	"github.com/jacobsa/crypto/common"
)

// Given strings A and B with len(A) >= len(B), return a new slice consisting
// of B xor'd onto the right end of A. This matches the xorend operator of RFC
// 5297.
func xorend(a, b []byte) []byte {
	aLen := len(a)
	bLen := len(b)

	if aLen < bLen {
		panic("Invalid lengths.")
	}

	result := make([]byte, aLen)
	copy(result, a)

	difference := aLen - bLen
	tmp := make([]byte, bLen)
	common.Xor(tmp, a[difference:], b)

	copy(result[difference:], tmp)

	return result
}
