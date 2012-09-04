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
	associatedData := [][]byte{}

	f := func() { s2v(key, associatedData) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *S2vTest) ShortKey() {
	key := make([]byte, 15)
	associatedData := [][]byte{}

	f := func() { s2v(key, associatedData) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *S2vTest) LongKey() {
	key := make([]byte, 17)
	associatedData := [][]byte{}

	f := func() { s2v(key, associatedData) }
	ExpectThat(f, Panics(HasSubstr("16-byte")))
}

func (t *S2vTest) Rfc5297GoldenTestCaseA1() {
	key := fromRfcHex(
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0" +
		"f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")

	associatedData := [][]byte{
		fromRfcHex(
			"10111213 14151617 18191a1b 1c1d1e1f" +
			"20212223 24252627"),
	}

	expected := fromRfcHex("85632d07 c6e8f37f 950acd32 0a2ecc93")

	ExpectThat(s2v(key, associatedData), DeepEquals(expected))
}

func (t *S2vTest) Rfc5297GoldenTestCaseA2() {
	ExpectEq("TODO", "")
}

func (t *S2vTest) GeneratedTestCases() {
	ExpectEq("TODO", "")
}
