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

package testing

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// FromRfcHex decodes a hex string that may contain spaces, as used in test vectors in
// RFCs. Panic if the input is illegal.
func FromRfcHex(s string) []byte {
	// Remove spaces.
	s = strings.Replace(s, " ", "", -1)

	// Decode.
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid hex: %s", s))
	}

	return res
}
