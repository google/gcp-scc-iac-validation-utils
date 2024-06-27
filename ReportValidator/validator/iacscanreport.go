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

// package validator evaluates the IaC report voilation against the
// threshold limit.
package validator

import (
	"fmt"
	"strings"

	"github.com/google/gcp-scc-iac-validation-utils/templates"
)

func EvaluateIACScanReport(iacReport templates.IACReportTemplate, thresholds map[string]int, operator string) (bool, error) {
	severityCounts, err := fetchViolationFromIACReport(iacReport)
	if err != nil {
		return false, fmt.Errorf("fetchVoilationFromIACReport(): %v", err)
	}

	failureCriteriaViolations := computeViolationState(severityCounts, thresholds)

	return isBreachingThreshold(operator, failureCriteriaViolations)
}

func computeViolationState(severityCounts map[string]int, thresholds map[string]int) map[string]bool {
	failureCriteriaViolations := make(map[string]bool)

	for k, t := range thresholds {
		severity := strings.ToUpper(k)

		if severityCounts[severity] == 0 {
			failureCriteriaViolations[severity] = false
			continue
		}

		failureCriteriaViolations[severity] = severityCounts[severity] >= t
	}

	return failureCriteriaViolations
}

func isBreachingThreshold(operator string, failureCriteriaViolations map[string]bool) (bool, error) {
	switch operator {
	case "AND":
		return all(failureCriteriaViolations), nil
	case "OR":
		return any(failureCriteriaViolations), nil
	default:
		return true, fmt.Errorf("invalid severity operator: %v", operator)
	}
}

func all(failureCriteriaViolations map[string]bool) bool {
	if len(failureCriteriaViolations) == 0 {
		return false
	}

	for _, v := range failureCriteriaViolations {
		if !v {
			return false
		}
	}
	return true
}

func any(failureCriteriaViolations map[string]bool) bool {
	if len(failureCriteriaViolations) == 0 {
		return false
	}

	for _, v := range failureCriteriaViolations {
		if v {
			return true
		}
	}
	return false
}

func fetchViolationFromIACReport(iacReport templates.IACReportTemplate) (map[string]int, error) {
	severityCounts := make(map[string]int)

	for _, v := range iacReport.Response.IacValidationReport.Violations {
		s := strings.ToUpper(v.Severity)
		if !(s == "CRITICAL" || s == "HIGH" || s == "MEDIUM" || s == "LOW") {
			return nil, fmt.Errorf("invalid severity expression: %s", s)
		}

		severityCounts[strings.ToUpper(v.Severity)]++
	}

	return severityCounts, nil
}
