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
	"testing"

	aes_testing "github.com/jacobsa/crypto/testing"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
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

	f := func() { s2v(key, strings, nil) }
	ExpectThat(f, Panics(HasSubstr("-byte")))
}

func (t *S2vTest) ShortKey() {
	key := make([]byte, 15)
	strings := [][]byte{[]byte{}}

	f := func() { s2v(key, strings, nil) }
	ExpectThat(f, Panics(HasSubstr("-byte")))
}

func (t *S2vTest) LongKey() {
	key := make([]byte, 33)
	strings := [][]byte{[]byte{}}

	f := func() { s2v(key, strings, nil) }
	ExpectThat(f, Panics(HasSubstr("-byte")))
}

func (t *S2vTest) EmptyStringsVector() {
	key := aes_testing.FromRfcHex("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0")
	strings := [][]byte{}

	f := func() { s2v(key, strings, nil) }
	ExpectThat(f, Panics(HasSubstr("non-empty")))
}

func (t *S2vTest) Rfc5297GoldenTestCaseA1() {
	key := aes_testing.FromRfcHex("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0")

	strings := [][]byte{
		aes_testing.FromRfcHex(
			"10111213 14151617 18191a1b 1c1d1e1f" +
				"20212223 24252627"),
		aes_testing.FromRfcHex(
			"11223344 55667788 99aabbcc ddee"),
	}

	expected := aes_testing.FromRfcHex("85632d07 c6e8f37f 950acd32 0a2ecc93")

	ExpectThat(s2v(key, strings, nil), DeepEquals(expected))
}

func (t *S2vTest) Rfc5297GoldenTestCaseA2() {
	key := aes_testing.FromRfcHex("7f7e7d7c 7b7a7978 77767574 73727170")

	strings := [][]byte{
		aes_testing.FromRfcHex(
			"00112233 44556677 8899aabb ccddeeff" +
				"deaddada deaddada ffeeddcc bbaa9988" +
				"77665544 33221100"),
		aes_testing.FromRfcHex("10203040 50607080 90a0"),
		aes_testing.FromRfcHex("09f91102 9d74e35b d84156c5 635688c0"),
		aes_testing.FromRfcHex(
			"74686973 20697320 736f6d65 20706c61" +
				"696e7465 78742074 6f20656e 63727970" +
				"74207573 696e6720 5349562d 414553"),
	}

	expected := aes_testing.FromRfcHex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f")

	ExpectThat(s2v(key, strings, nil), DeepEquals(expected))
}

func (t *S2vTest) GeneratedTestCases() {
	cases := aes_testing.S2vCases()
	AssertGe(len(cases), 100)

	for i, c := range cases {
		ExpectThat(
			s2v(c.Key, c.Strings, nil),
			DeepEquals(c.Output),
			"Case %d: %v", i, c)
	}
}
