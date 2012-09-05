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

// EncryptTestCase represents a test case for Encrypt() generated using a
// reference implementation.
type EncryptTestCase struct {
	Key []byte
	Plaintext []byte
	Associated [][]byte
	Output []byte
}

func (c EncryptTestCase) String() string {
	return fmt.Sprintf(
		"Encrypt(%x, %x, %v) = %x",
		c.Key,
		c.Plaintext,
		c.Associated,
		c.Output)
}

// EncryptTestCases returns test cases for Encrypt.
func EncryptCases() []EncryptTestCase {
	// Find the source package.
	pkg, err := build.Import(
		"github.com/jacobsa/aes/testing/cases",
		"",
		build.FindOnly)

	if err != nil {
		panic(fmt.Sprintf("Finding package: %v", err))
	}

	// Load the appropriate gob file.
	gobPath := path.Join(pkg.Dir, "encrypt.gob")
	f, err := os.Open(gobPath)
	if err != nil {
		panic(fmt.Sprintf("Opening %s: %v", gobPath, err))
	}

	defer f.Close()

	// Parse it.
	var cases []EncryptTestCase
	if err = gob.NewDecoder(f).Decode(&cases); err != nil {
		panic(fmt.Sprintf("Decoding: %v", err))
	}

	// Make sure the plaintext field is non-nil for all cases so that it can
	// easily be used with a DeepEquals matcher. Gob decoding does not seem to
	// preserve this.
	for i, _ := range cases {
		c := &cases[i]
		if c.Plaintext == nil {
			c.Plaintext = []byte{}
		}
	}

	return cases
}
