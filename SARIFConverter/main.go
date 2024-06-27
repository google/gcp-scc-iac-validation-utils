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

// Package main converts IaC validation report to SARIF JSON format.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/gcp-scc-iac-validation-utils/SARIFConverter/converter"
	"github.com/google/gcp-scc-iac-validation-utils/templates"
)

var (
	inputFilePath  = flag.String("inputFilePath", "", "path of the input file")
	outputFilePath = flag.String("outputFilePath", "output.json", "path of the output file")
)

func main() {
	flag.Parse()

	iacReport, err := readAndParseIACScanReport(inputFilePath)
	if err != nil {
		fmt.Printf("readAndParseIACScanReport: %v", err)
		os.Exit(1)
	}

	sarifReport, err := converter.FromIACScanReport(iacReport.Response.IacValidationReport)
	if err != nil {
		fmt.Printf("converter.FromIACScanReport: %v", err)
		os.Exit(1)
	}

	if err := writeSarifReport(sarifReport, outputFilePath); err != nil {
		fmt.Printf("writeSarifReport(): %v", err)
		os.Exit(1)
	}
}

func readAndParseIACScanReport(filePath *string) (templates.IACReportTemplate, error) {
	data, err := os.ReadFile(*filePath)
	if err != nil {
		return templates.IACReportTemplate{}, fmt.Errorf("os.ReadFile(%s): %v", *filePath, err)
	}

	var iacReport templates.IACReportTemplate
	if err = json.Unmarshal(data, &iacReport); err != nil {
		return templates.IACReportTemplate{}, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return iacReport, nil
}

func writeSarifReport(sarifReport templates.SarifOutput, outputFilePath *string) error {
	sarifJSON, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("json.MarshalIndent: %v", err)
	}

	outputJSON, err := os.Create(*outputFilePath)
	if err != nil {
		return fmt.Errorf("os.Create: %v", err)
	}
	defer outputJSON.Close()

	_, err = outputJSON.Write(sarifJSON)
	if err != nil {
		return fmt.Errorf("outputJSON.Write: %v", err)
	}

	return nil
}
