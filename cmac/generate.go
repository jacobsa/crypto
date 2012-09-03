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
	"fmt"
)

// Given a 128-bit key and a message, return a MAC that can be used to validate
// the input message. This is the AES-CMAC function of RFC 4493.
func generateCmac(key []byte, msg []byte) ([]byte, error) {
	return nil, fmt.Errorf("TODO")
}
