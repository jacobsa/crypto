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
	"crypto/aes"
	"crypto/des"
	aes_testing "github.com/jacobsa/aes/testing"
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

func (t *SubkeyTest) WrongBlockSize() {
	ciph, err := des.NewCipher(make([]byte, 8))
	AssertEq(nil, err)

	f := func() { generateSubkeys(ciph) }
	ExpectThat(f, Panics(HasSubstr("16 bytes")))
}

func (t *SubkeyTest) NistTestCaseD1() {
	key := aes_testing.FromRfcHex("2b7e1516 28aed2a6 abf71588 09cf4f3c")
	expectedK1 := aes_testing.FromRfcHex("fbeed618 35713366 7c85e08f 7236a8de")
	expectedK2 := aes_testing.FromRfcHex("f7ddac30 6ae266cc f90bc11e e46d513b")

	ciph, err := aes.NewCipher(key)
	AssertEq(nil, err)

	k1, k2 := generateSubkeys(ciph)
	ExpectThat(k1, DeepEquals(expectedK1))
	ExpectThat(k2, DeepEquals(expectedK2))
}

func (t *SubkeyTest) NistTestCaseD2() {
	key := aes_testing.FromRfcHex(
		"8e73b0f7 da0e6452 c810f32b 809079e5" +
		"62f8ead2 522c6b7b")

	expectedK1 := aes_testing.FromRfcHex("448a5b1c 93514b27 3ee6439d d4daa296")
	expectedK2 := aes_testing.FromRfcHex("8914b639 26a2964e 7dcc873b a9b5452c")

	ciph, err := aes.NewCipher(key)
	AssertEq(nil, err)

	k1, k2 := generateSubkeys(ciph)
	ExpectThat(k1, DeepEquals(expectedK1))
	ExpectThat(k2, DeepEquals(expectedK2))
}

func (t *SubkeyTest) NistTestCaseD3() {
	key := aes_testing.FromRfcHex(
		"603deb10 15ca71be 2b73aef0 857d7781" +
		"1f352c07 3b6108d7 2d9810a3 0914dff4")

	expectedK1 := aes_testing.FromRfcHex("cad1ed03 299eedac 2e9a9980 8621502f")
	expectedK2 := aes_testing.FromRfcHex("95a3da06 533ddb58 5d353301 0c42a0d9")

	ciph, err := aes.NewCipher(key)
	AssertEq(nil, err)

	k1, k2 := generateSubkeys(ciph)
	ExpectThat(k1, DeepEquals(expectedK1))
	ExpectThat(k2, DeepEquals(expectedK2))
}

func (t *SubkeyTest) GeneratedTestCases() {
	cases := aes_testing.GenerateSubkeyCases()
	AssertGe(len(cases), 100)

	for i, c := range cases {
		ciph, err := aes.NewCipher(c.Key)
		AssertEq(nil, err)

		k1, k2 := generateSubkeys(ciph)
		ExpectThat(k1, DeepEquals(c.K1), "Test case %d: %v", i, c)
		ExpectThat(k2, DeepEquals(c.K2), "Test case %d: %v", i, c)
	}
}
