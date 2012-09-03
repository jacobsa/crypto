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
	"encoding/gob"
	"fmt"
	"go/build"
	"os"
	"path"
)

// GenerateCmacTestCase represents a test case for generateCmac generated using
// the reference implementation from RFC 4493.
type GenerateCmacTestCase struct {
	Key []byte
	Msg []byte
	Mac []byte
}

func (c GenerateCmacTestCase) String() string {
	return fmt.Sprintf("generateCmac(%x, %x) = %x", c.Key, c.Msg, c.Mac)
}

// GenerateCmacTestCases returns test cases for generateCmac.
func GenerateCmacCases() []GenerateCmacTestCase {
	// Find the source package.
	pkg, err := build.Import(
		"github.com/jacobsa/aes/testing/cases",
		"",
		build.FindOnly)

	if err != nil {
		panic(fmt.Sprintf("Finding package: %v", err))
	}

	// Load the appropriate gob file.
	gobPath := path.Join(pkg.Dir, "generateCmac.gob")
	f, err := os.Open(gobPath)
	if err != nil {
		panic(fmt.Sprintf("Opening %s: %v", gobPath, err))
	}

	defer f.Close()

	// Parse it.
	var cases []GenerateCmacTestCase
	if err = gob.NewDecoder(f).Decode(&cases); err != nil {
		panic(fmt.Sprintf("Decoding: %v", err))
	}

	return cases
}
