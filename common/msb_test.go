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
	"github.com/jacobsa/crypto/common"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
	"strconv"
	"testing"
)

func TestMsb(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

func fromBinary(s string) byte {
	AssertEq(8, len(s), "%s", s)

	u, err := strconv.ParseUint(s, 2, 8)
	AssertEq(nil, err, "%s", s)

	return byte(u)
}

type MsbTest struct{}

func init() { RegisterTestSuite(&MsbTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *MsbTest) NilBuffer() {
	f := func() { common.Msb(nil) }
	ExpectThat(f, Panics(HasSubstr("empty")))
}

func (t *MsbTest) EmptyBuffer() {
	f := func() { common.Msb([]byte{}) }
	ExpectThat(f, Panics(HasSubstr("empty")))
}

func (t *MsbTest) MostSignficantIsOne() {
	bufs := [][]byte{
		[]byte{fromBinary("10000000")},
		[]byte{fromBinary("11000000")},
		[]byte{fromBinary("11100000")},
		[]byte{fromBinary("10000000"), fromBinary("00000000")},
	}

	for i, buf := range bufs {
		ExpectEq(1, common.Msb(buf), "Test case %d: %v", i, buf)
	}
}

func (t *MsbTest) MostSignficantIsZero() {
	bufs := [][]byte{
		[]byte{fromBinary("00000000")},
		[]byte{fromBinary("01000000")},
		[]byte{fromBinary("01100000")},
		[]byte{fromBinary("00000000"), fromBinary("10000000")},
	}

	for i, buf := range bufs {
		ExpectEq(0, common.Msb(buf), "Test case %d: %v", i, buf)
	}
}
