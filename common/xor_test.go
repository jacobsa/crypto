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

package common_test

import (
	"testing"

	"github.com/jacobsa/crypto/common"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
)

func TestXor(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type XorTest struct{}

func init() { RegisterTestSuite(&XorTest{}) }

func xorWithResult(a []byte, b []byte) (result []byte) {
	result = make([]byte, len(a))
	common.Xor(result, a, b)
	return
}

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *XorTest) LengthsNotEqual() {
	a := []byte{0x00}
	b := []byte{0x00, 0x11}
	f := func() { xorWithResult(a, b) }
	ExpectThat(f, Panics(HasSubstr("length")))
}

func (t *XorTest) NilBuffers() {
	a := []byte(nil)
	b := []byte(nil)
	result := xorWithResult(a, b)

	AssertNe(nil, result)
	ExpectThat(result, DeepEquals([]byte{}))
}

func (t *XorTest) EmptyBuffers() {
	a := []byte{}
	b := []byte{}
	result := xorWithResult(a, b)

	AssertNe(nil, result)
	ExpectThat(result, DeepEquals([]byte{}))
}

func (t *XorTest) OneByteBuffers() {
	var a, b, expected []byte

	a = []byte{fromBinary("00000000")}
	b = []byte{fromBinary("00000000")}
	expected = []byte{fromBinary("00000000")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))

	a = []byte{fromBinary("11111111")}
	b = []byte{fromBinary("11111111")}
	expected = []byte{fromBinary("00000000")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))

	a = []byte{fromBinary("11111111")}
	b = []byte{fromBinary("00000000")}
	expected = []byte{fromBinary("11111111")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))

	a = []byte{fromBinary("00000000")}
	b = []byte{fromBinary("11111111")}
	expected = []byte{fromBinary("11111111")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))

	a = []byte{fromBinary("10100100")}
	b = []byte{fromBinary("11111111")}
	expected = []byte{fromBinary("01011011")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))
}

func (t *XorTest) MultiByteBuffers() {
	var a, b, expected []byte

	a = []byte{fromBinary("00000000"), fromBinary("00000000")}
	b = []byte{fromBinary("00000000"), fromBinary("00000000")}
	expected = []byte{fromBinary("00000000"), fromBinary("00000000")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))

	a = []byte{fromBinary("11111111"), fromBinary("11111111")}
	b = []byte{fromBinary("11111111"), fromBinary("11111111")}
	expected = []byte{fromBinary("00000000"), fromBinary("00000000")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))

	a = []byte{fromBinary("00000000"), fromBinary("11111111")}
	b = []byte{fromBinary("11111111"), fromBinary("00000000")}
	expected = []byte{fromBinary("11111111"), fromBinary("11111111")}
	ExpectThat(xorWithResult(a, b), DeepEquals(expected))
}
