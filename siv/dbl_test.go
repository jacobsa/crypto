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

func TestDbl(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type DblTest struct{}

func init() { RegisterTestSuite(&DblTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *DblTest) NilBuffer() {
	f := func() { dbl(nil) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *DblTest) ShortBuffer() {
	f := func() { dbl(make([]byte, 15)) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *DblTest) LongBuffer() {
	f := func() { dbl(make([]byte, 17)) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *DblTest) RfcTestCases() {
	type testCase struct {
		iHex string
		oHex string
	}

	cases := []testCase{
		testCase{
			"0e04dfaf c1efbf04 01405828 59bf073a",
			"1c09bf5f 83df7e08 0280b050 b37e0e74",
		},
		testCase{
			"edf09de8 76c642ee 4d78bce4 ceedfc4f",
			"dbe13bd0 ed8c85dc 9af179c9 9ddbf819",
		},
		testCase{
			"0e04dfaf c1efbf04 01405828 59bf073a",
			"1c09bf5f 83df7e08 0280b050 b37e0e74",
		},
		testCase{
			"c8b43b59 74960e7c e6a5dd85 231e591a",
			"916876b2 e92c1cf9 cd4bbb0a 463cb2b3",
		},
		testCase{
			"adf31e28 5d3d1e1d 4ddefc1e 5bec63e9",
			"5be63c50 ba7a3c3a 9bbdf83c b7d8c755",
		},
		testCase{
			"826aa75b 5e568eed 3125bfb2 66c61d4e",
			"04d54eb6 bcad1dda 624b7f64 cd8c3a1b",
		},
	}

	for i, c := range cases {
		input := aes_testing.FromRfcHex(c.iHex)
		expected := aes_testing.FromRfcHex(c.oHex)
		ExpectThat(dbl(input), DeepEquals(expected), "Case %d: %v", i, c)
	}
}

func (t *DblTest) GeneratedTestCases() {
	cases := aes_testing.DblCases()
	AssertGe(len(cases), 100)

	for i, c := range cases {
		ExpectThat(dbl(c.Input), DeepEquals(c.Output), "Case %d: %v", i, c)
	}
}
