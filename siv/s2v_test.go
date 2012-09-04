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

package siv

import (
	aes_testing "github.com/jacobsa/aes/testing"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestS2v(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type S2vTest struct{}

func init() { RegisterTestSuite(&S2vTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *S2vTest) NilKey() {
	key := []byte(nil)
	strings := [][]byte{[]byte{}}

	f := func() { s2v(key, strings) }
	ExpectThat(f, Panics(HasSubstr("-byte")))
}

func (t *S2vTest) ShortKey() {
	key := make([]byte, 15)
	strings := [][]byte{[]byte{}}

	f := func() { s2v(key, strings) }
	ExpectThat(f, Panics(HasSubstr("-byte")))
}

func (t *S2vTest) LongKey() {
	key := make([]byte, 33)
	strings := [][]byte{[]byte{}}

	f := func() { s2v(key, strings) }
	ExpectThat(f, Panics(HasSubstr("-byte")))
}

func (t *S2vTest) EmptyStringsVector() {
	key := aes_testing.FromRfcHex(
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0" +
		"f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")

	strings := [][]byte{}

	f := func() { s2v(key, strings) }
	ExpectThat(f, Panics(HasSubstr("non-empty")))
}

func (t *S2vTest) Rfc5297GoldenTestCaseA1() {
	key := aes_testing.FromRfcHex(
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0" +
		"f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")

	strings := [][]byte{
		aes_testing.FromRfcHex(
			"10111213 14151617 18191a1b 1c1d1e1f" +
			"20212223 24252627"),
	}

	expected := aes_testing.FromRfcHex("85632d07 c6e8f37f 950acd32 0a2ecc93")

	ExpectThat(s2v(key, strings), DeepEquals(expected))
}

func (t *S2vTest) Rfc5297GoldenTestCaseA2() {
	key := aes_testing.FromRfcHex(
		"7f7e7d7c 7b7a7978 77767574 73727170" +
		"40414243 44454647 48494a4b 4c4d4e4f")

	strings := [][]byte{
		aes_testing.FromRfcHex(
			"00112233 44556677 8899aabb ccddeeff" +
			"deaddada deaddada ffeeddcc bbaa9988" +
			"77665544 33221100"),
		aes_testing.FromRfcHex("10203040 50607080 90a0"),
	}

	expected := aes_testing.FromRfcHex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f")

	ExpectThat(s2v(key, strings), DeepEquals(expected))
}

func (t *S2vTest) GeneratedTestCases() {
	cases := aes_testing.S2vCases()
	AssertGe(len(cases), 100)

	for i, c := range cases {
		ExpectThat(s2v(c.Key, c.Strings), DeepEquals(c.Output), "Case %d: %v", i, c)
	}
}
