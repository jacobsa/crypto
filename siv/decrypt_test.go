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

package siv_test

import (
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestDecrypt(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type DecryptTest struct{}

func init() { RegisterTestSuite(&DecryptTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *DecryptTest) NilKey() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) ShortKey() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) LongKey() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) TooMuchAssociatedData() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) JustLittleEnoughAssociatedData() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) DoesntClobberAssociatedSlice() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) WrongKey() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) Rfc5297TestCaseA1() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) Rfc5297TestCaseA2() {
	ExpectEq("TODO", "")
}

func (t *DecryptTest) GeneratedTestCases() {
	ExpectEq("TODO", "")
}
