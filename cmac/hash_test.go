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
	aes_testing "github.com/jacobsa/aes/testing"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestHash(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type HashTest struct{}

func init() { RegisterTestSuite(&HashTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *HashTest) NilKey() {
	_, err := generateCmac(nil, []byte{})
	ExpectThat(err, Error(HasSubstr("16-byte")))
}

func (t *HashTest) ShortKey() {
	_, err := generateCmac(make([]byte, 15), []byte{})
	ExpectThat(err, Error(HasSubstr("16-byte")))
}

func (t *HashTest) LongKey() {
	_, err := generateCmac(make([]byte, 17), []byte{})
	ExpectThat(err, Error(HasSubstr("16-byte")))
}

func (t *HashTest) NilMessage() {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	AssertEq(nil, err)

	var msg []byte = nil

	expectedMac, err := hex.DecodeString("bb1d6929e95937287fa37d129b756746")
	AssertEq(nil, err)

	mac, err := generateCmac(key, msg)
	AssertEq(nil, err)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase1() {
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

func (t *HashTest) Rfc4493GoldenTestCase2() {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	AssertEq(nil, err)

	msg, err := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	AssertEq(nil, err)

	expectedMac, err := hex.DecodeString("070a16b46b4d4144f79bdd9dd04a287c")
	AssertEq(nil, err)

	mac, err := generateCmac(key, msg)
	AssertEq(nil, err)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase3() {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	AssertEq(nil, err)

	msg, err := hex.DecodeString(
		"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411")
	AssertEq(nil, err)

	expectedMac, err := hex.DecodeString("dfa66747de9ae63030ca32611497c827")
	AssertEq(nil, err)

	mac, err := generateCmac(key, msg)
	AssertEq(nil, err)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase4() {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	AssertEq(nil, err)

	msg, err := hex.DecodeString(
		"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411e5fbc1191a0a52ef" +
			"f69f2445df4f9b17ad2b417be66c3710")
	AssertEq(nil, err)

	expectedMac, err := hex.DecodeString("51f0bebf7e3b9d92fc49741779363cfe")
	AssertEq(nil, err)

	mac, err := generateCmac(key, msg)
	AssertEq(nil, err)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) GeneratedTestCases() {
	cases := aes_testing.GenerateCmacCases()
	AssertGe(len(cases), 100)

	for i, c := range cases {
		mac, err := generateCmac(c.Key, c.Msg)
		AssertEq(nil, err)
		ExpectThat(mac, DeepEquals(c.Mac), "Test case %d: %v", i, c)
	}
}
