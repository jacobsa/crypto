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

func TestGenerate(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type GenerateTest struct{}

func init() { RegisterTestSuite(&GenerateTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *GenerateTest) NilKey() {
	_, err := generateCmac(nil, []byte{})
	ExpectThat(err, Error(HasSubstr("16-byte")))
}

func (t *GenerateTest) ShortKey() {
	_, err := generateCmac(make([]byte, 15), []byte{})
	ExpectThat(err, Error(HasSubstr("16-byte")))
}

func (t *GenerateTest) LongKey() {
	_, err := generateCmac(make([]byte, 17), []byte{})
	ExpectThat(err, Error(HasSubstr("16-byte")))
}

func (t *GenerateTest) NilMessage() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase1() {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	AssertEq(nil, err)

	msg, err := hex.DecodeString("")
	AssertEq(nil, err)

	expectedMac, err := hex.DecodeString("bb1d6929e95937287fa37d129b756746")
	AssertEq(nil, err)

	mac, err := generateCmac(key, msg)
	AssertEq(nil, err)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *GenerateTest) Rfc4493GoldenTestCase2() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase3() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase4() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) GeneratedTestCases() {
	ExpectEq("TODO", "")
}
