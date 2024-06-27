/*
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

// Package main checks the scc iac-validation-report against the failure 
// criteria and returns the validation state.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/gcp-scc-iac-validation-utils/ReportValidator/expressionprocessor"
	"github.com/google/gcp-scc-iac-validation-utils/ReportValidator/validator"
	"github.com/google/gcp-scc-iac-validation-utils/templates"
)

var (
	inputFilePath      = flag.String("inputFilePath", "", "path of the json file")
	failure_expression = flag.String("failure_expression", "", "condition for validation")
)

func main() {
	flag.Parse()

	operator, thresholds, err := expressionprocessor.ParseFailureExpression(*failure_expression)
	if err != nil {
		fmt.Printf("Failure while procession the failure_expression: %v", err)
		os.Exit(1)
	}

	report, err := readAndParseIACScanReport(inputFilePath)
	if err != nil {
		fmt.Printf("Failure while reading and parsing IAC scan report: %v", err)
		os.Exit(1)
	}

	isBreachingThreshold, err := validator.EvaluateIACScanReport(report, thresholds, operator)
	if err != nil {
		fmt.Printf("Failure occured during validation: %v", err)
		os.Exit(1)
	}

	if isBreachingThreshold {
		fmt.Printf("Validation Failed! Severity exceeding voilation threshold.")
		os.Exit(1)
	}

	fmt.Println("Validation Succeeded!")
}

func readAndParseIACScanReport(inputFilePath *string) (templates.IACReportTemplate, error) {
	data, err := os.ReadFile(*inputFilePath)
	if err != nil {
		return templates.IACReportTemplate{}, fmt.Errorf("os.ReadFile(%s): %v", *inputFilePath, err)
	}

	var iacReport templates.IACReportTemplate
	if err = json.Unmarshal(data, &iacReport); err != nil {
		return templates.IACReportTemplate{}, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return iacReport, nil
}
