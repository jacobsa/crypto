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

package common

// Xor computes `a XOR b`, as defined by RFC 4493.
func Xor(a []byte, b []byte) []byte {
	if len(a) != len(b) {
		panic("Xor requires buffers to have identical lengths.")
	}

	output := make([]byte, len(a))
	for i, _ := range a {
		output[i] = a[i] ^ b[i]
	}

	return output
}
