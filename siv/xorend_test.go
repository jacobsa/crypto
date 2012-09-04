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
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestXorend(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type XorendTest struct{}

func init() { RegisterTestSuite(&XorendTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *XorendTest) AShorterThanB() {
	ExpectEq("TODO", "")
}

func (t *XorendTest) BothAreNil() {
	ExpectEq("TODO", "")
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
