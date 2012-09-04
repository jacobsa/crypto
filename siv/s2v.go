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

// Run the S2V "string to vector" function of RFC 5297 using the input key and
// string vector, which must be non-empty. (RFC 5297 defines S2V to handle the
// empty vector case, but it is never used that way by higher-level functions.)
func s2v(key []byte, strings [][]byte) []byte {
	if len(strings) == 0 {
		panic("strings vector must be non-empty.")
	}

	panic("TODO")
}
