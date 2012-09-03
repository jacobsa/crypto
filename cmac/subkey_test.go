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
	"encoding/hex"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestSubkey(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type SubkeyTest struct{}

func init() { RegisterTestSuite(&SubkeyTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *SubkeyTest) NilKey() {
	f := func() { generateSubkey(nil) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *SubkeyTest) KeyTooShort() {
	key := make([]byte, 15)
	f := func() { generateSubkey(key) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *SubkeyTest) KeyTooLong() {
	key := make([]byte, 17)
	f := func() { generateSubkey(key) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *SubkeyTest) Rfc4493GoldenTestCase() {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	AssertEq(nil, err)

	expectedK1, err := hex.DecodeString("fbeed618357133667c85e08f7236a8de")
	AssertEq(nil, err)

	expectedK2, err := hex.DecodeString("f7ddac306ae266ccf90bc11ee46d513b")
	AssertEq(nil, err)

	k1, k2 := generateSubkey(key)
	ExpectThat(k1, DeepEquals(expectedK1))
	ExpectThat(k2, DeepEquals(expectedK2))
}
