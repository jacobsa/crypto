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
	"strconv"
	"testing"
)

func TestXorend(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

func fromBinary(s string) byte {
	AssertEq(8, len(s), "%s", s)

	u, err := strconv.ParseUint(s, 2, 8)
	AssertEq(nil, err, "%s", s)

	return byte(u)
}

type XorendTest struct{}

func init() { RegisterTestSuite(&XorendTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *XorendTest) AIsShorterThanB() {
	a := []byte{0xde}
	b := []byte{0xde, 0xad}

	f := func() { xorend(a, b) }
	ExpectThat(f, Panics(HasSubstr("length")))
}

func (t *XorendTest) BothAreNil() {
	a := []byte(nil)
	b := []byte(nil)

	expected := []byte{}
	ExpectThat(xorend(a, b), DeepEquals(expected))
}

func (t *XorendTest) BIsNil() {
	ExpectEq("TODO", "")
}

func (t *XorendTest) BothAreEmpty() {
	ExpectEq("TODO", "")
}

func (t *XorendTest) BIsEmpty() {
	ExpectEq("TODO", "")
}

func (t *XorendTest) BIsNonEmpty() {
	ExpectEq("TODO", "")
}
