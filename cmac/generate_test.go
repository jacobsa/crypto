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
	. "github.com/jacobsa/ogletest"
	"testing"
)

func TestGenerate(t *testing.T) { RunTests(t) }

////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////

type GenerateTest struct{}

func init() { RegisterTestSuite(&GenerateTest{}) }

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

func (t *GenerateTest) NilKey() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) ShortKey() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) LongKey() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) NilMessage() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) EmptyMessage() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase1() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase2() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase3() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) Rfc4493GoldenTestCase4() {
	ExpectEq("TODO", "")
}

func (t *GenerateTest) GeneratedTestCases() {
	ExpectEq("TODO", "")
}
