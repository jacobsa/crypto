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

// S2vTestCase represents a test case for S2V() generated using a reference
// implementation.
type S2vTestCase struct {
	Key     []byte
	Strings [][]byte
	Output  []byte
}

func (c S2vTestCase) String() string {
	return fmt.Sprintf("S2v(%x, %x) = %x", c.Key, c.Strings, c.Output)
}

// S2vTestCases returns test cases for S2V.
func S2vCases() []S2vTestCase {
	// Find the source package.
	pkg, err := build.Import(
		"github.com/jacobsa/aes/testing/cases",
		"",
		build.FindOnly)

	if err != nil {
		panic(fmt.Sprintf("Finding package: %v", err))
	}

	// Load the appropriate gob file.
	gobPath := path.Join(pkg.Dir, "s2v.gob")
	f, err := os.Open(gobPath)
	if err != nil {
		panic(fmt.Sprintf("Opening %s: %v", gobPath, err))
	}

	defer f.Close()

	// Parse it.
	var cases []S2vTestCase
	if err = gob.NewDecoder(f).Decode(&cases); err != nil {
		panic(fmt.Sprintf("Decoding: %v", err))
	}

	return cases
}
