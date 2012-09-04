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
	"bytes"
	"encoding/hex"
	"github.com/jacobsa/aes/common"
	. "github.com/jacobsa/oglematchers"
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestPadBlock(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type PadBlockTest struct{}

func init() { RegisterTestSuite(&PadBlockTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *PadBlockTest) FullBlock() {
	b := make([]byte, 16)
	f := func() { common.PadBlock(b) }
	ExpectThat(f, Panics(HasSubstr("16 bytes")))
}

func (t *PadBlockTest) LongBlock() {
	b := make([]byte, 17)
	f := func() { common.PadBlock(b) }
	ExpectThat(f, Panics(HasSubstr("16 bytes")))
}

func (t *PadBlockTest) OneByteMissing() {
	b, err := hex.DecodeString("deadbeeffeedfaceba5eba11cafeba")
	AssertEq(nil, err)
	AssertEq(15, len(b))

	expected := append(b, 0x80)
	ExpectThat(common.PadBlock(b), DeepEquals(expected))
}

func (t *PadBlockTest) MultipleBytesMissing() {
	b, err := hex.DecodeString("deadbeeffeedfaceba5eba11ca")
	AssertEq(nil, err)
	AssertEq(13, len(b))

	expected := append(b, 0x80, 0x00, 0x00)
	ExpectThat(common.PadBlock(b), DeepEquals(expected))
}

func (t *PadBlockTest) AllBytesMissing() {
	b := []byte{}
	expected := append([]byte{0x80}, bytes.Repeat([]byte{0x00}, 15)...)
	ExpectThat(common.PadBlock(b), DeepEquals(expected))
}
