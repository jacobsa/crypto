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

package cmac_test

import (
	"github.com/jacobsa/aes/cmac"
	aes_testing "github.com/jacobsa/aes/testing"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestHash(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

func runCmac(key []byte, msg []byte) []byte {
	h, err := cmac.New(key)
	AssertEq(nil, err)

	_, err = h.Write(msg)
	AssertEq(nil, err)

	return h.Sum([]byte{})
}

type HashTest struct{}

func init() { RegisterTestSuite(&HashTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *HashTest) NilKey() {
	_, err := cmac.New(nil)
	ExpectThat(err, Error(HasSubstr("16-")))
	ExpectThat(err, Error(HasSubstr("24-")))
	ExpectThat(err, Error(HasSubstr("32-")))
}

func (t *HashTest) ShortKey() {
	_, err := cmac.New(make([]byte, 15))
	ExpectThat(err, Error(HasSubstr("16-")))
	ExpectThat(err, Error(HasSubstr("24-")))
	ExpectThat(err, Error(HasSubstr("32-")))
}

func (t *HashTest) LongKey() {
	_, err := cmac.New(make([]byte, 33))
	ExpectThat(err, Error(HasSubstr("16-")))
	ExpectThat(err, Error(HasSubstr("24-")))
	ExpectThat(err, Error(HasSubstr("32-")))
}

func (t *HashTest) SumAppendsToSlice() {
	// Grab a test case.
	cases := aes_testing.CmacCases()
	AssertGt(len(cases), 10)
	c := cases[10]

	// Create a hash and feed it the test case's data.
	h, err := cmac.New(c.Key)
	AssertEq(nil, err)

	_, err = h.Write(c.Msg)
	AssertEq(nil, err)

	// Ask it to append to a non-empty slice.
	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	mac := h.Sum(prefix)

	AssertEq(20, len(mac))
	ExpectThat(mac[0:4], DeepEquals(prefix))
	ExpectThat(mac[4:], DeepEquals(c.Mac))
}

func (t *HashTest) SumDoesntAffectState() {
	// Grab a test case.
	cases := aes_testing.CmacCases()
	AssertGt(len(cases), 10)
	c := cases[10]

	// Create a hash and feed it some of the test case's data.
	h, err := cmac.New(c.Key)
	AssertEq(nil, err)

	AssertGt(len(c.Msg), 5)
	_, err = h.Write(c.Msg[0:5])
	AssertEq(nil, err)

	// Call Sum.
	AssertEq(16, len(h.Sum([]byte{})))

	// Feed the rest of the data and call Sum again. We should get the correct
	// result.
	_, err = h.Write(c.Msg[5:])
	AssertEq(nil, err)

	ExpectThat(h.Sum([]byte{}), DeepEquals(c.Mac))

	// Calling repeatedly should also work.
	ExpectThat(h.Sum([]byte{}), DeepEquals(c.Mac))
	ExpectThat(h.Sum([]byte{}), DeepEquals(c.Mac))
	ExpectThat(h.Sum([]byte{}), DeepEquals(c.Mac))
}

func (t *HashTest) Reset() {
	// Grab a test case.
	cases := aes_testing.CmacCases()
	AssertGt(len(cases), 10)
	c := cases[10]

	// Create a hash and feed it some data, then reset it.
	h, err := cmac.New(c.Key)
	AssertEq(nil, err)

	_, err = h.Write([]byte{0xde, 0xad})
	AssertEq(nil, err)

	h.Reset()

	// Feed the hash the test case's data and make sure the result is correct.
	_, err = h.Write(c.Msg)
	AssertEq(nil, err)

	ExpectThat(h.Sum([]byte{}), DeepEquals(c.Mac))
}

func (t *HashTest) Size() {
	h, err := cmac.New(make([]byte, 16))
	AssertEq(nil, err)
	ExpectEq(16, h.Size())
}

func (t *HashTest) BlockSize() {
	h, err := cmac.New(make([]byte, 16))
	AssertEq(nil, err)
	ExpectEq(16, h.BlockSize())
}

func (t *HashTest) NilMessage() {
	key := aes_testing.FromRfcHex("2b7e1516 28aed2a6 abf71588 09cf4f3c")

	var msg []byte = nil

	expectedMac := aes_testing.FromRfcHex("bb1d6929 e9593728 7fa37d12 9b756746")

	mac := runCmac(key, msg)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase1() {
	key := aes_testing.FromRfcHex("2b7e1516 28aed2a6 abf71588 09cf4f3c")
	msg := aes_testing.FromRfcHex("")
	expectedMac := aes_testing.FromRfcHex("bb1d6929 e9593728 7fa37d12 9b756746")

	mac := runCmac(key, msg)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase2() {
	key := aes_testing.FromRfcHex("2b7e1516 28aed2a6 abf71588 09cf4f3c")
	msg := aes_testing.FromRfcHex("6bc1bee2 2e409f96 e93d7e11 7393172a")
	expectedMac := aes_testing.FromRfcHex("070a16b4 6b4d4144 f79bdd9d d04a287c")

	mac := runCmac(key, msg)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase3() {
	key := aes_testing.FromRfcHex("2b7e1516 28aed2a6 abf71588 09cf4f3c")

	msg := aes_testing.FromRfcHex(
		"6bc1bee2 2e409f96 e93d7e11 7393172a" +
		"ae2d8a57 1e03ac9c 9eb76fac 45af8e51" +
		"30c81c46 a35ce411")

	expectedMac := aes_testing.FromRfcHex("dfa66747 de9ae630 30ca3261 1497c827")

	mac := runCmac(key, msg)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) Rfc4493GoldenTestCase4() {
	key := aes_testing.FromRfcHex("2b7e1516 28aed2a6 abf71588 09cf4f3c")

	msg := aes_testing.FromRfcHex(
		"6bc1bee2 2e409f96 e93d7e11 7393172a" +
		"ae2d8a57 1e03ac9c 9eb76fac 45af8e51" +
		"30c81c46 a35ce411 e5fbc119 1a0a52ef" +
		"f69f2445 df4f9b17 ad2b417b e66c3710")

	expectedMac := aes_testing.FromRfcHex("51f0bebf 7e3b9d92 fc497417 79363cfe")

	mac := runCmac(key, msg)
	ExpectThat(mac, DeepEquals(expectedMac))
}

func (t *HashTest) GeneratedTestCases() {
	cases := aes_testing.CmacCases()
	AssertGe(len(cases), 100)

	for i, c := range cases {
		mac := runCmac(c.Key, c.Msg)
		ExpectThat(mac, DeepEquals(c.Mac), "Test case %d: %v", i, c)
	}
}
