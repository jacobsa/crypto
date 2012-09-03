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

package main

import (
	"flag"
	"fmt"
	"github.com/jacobsa/aes/testing"
	"log"
)

var function = flag.String("func", "", "Function for which to generate cases.")

func doGenerateSubkey() []testing.GenerateSubkeyTestCase {
	return nil
}

func main() {
	var cases interface{}
	switch *function {
	case "":
		log.Fatalf("You must set -func.")
	case "generateSubkey":
		cases = doGenerateSubkey()
	default:
		log.Fatalf("Unrecognized function: %s", *function)
	}

	fmt.Printf("Result: %v", cases)
}

