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

// package converter constructs the IaC SCC scan report in to SARIF json format.
package converter

import (
	"fmt"

	"github.com/google/gcp-scc-iac-validation-utils/templates"
)

const (
	VERSION                     = "1.0.0"
	SARIF_SCHEMA                = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	SARIF_VERSION               = "2.1.0"
	IAC_TOOL_DOCUMENTATION_LINK = "https://cloud.google.com/security-command-center/docs/validate-iac"
	IAC_TOOL_NAME               = "analyze-code-security-scc"
)

func FromIACScanReport(report templates.IACValidationReport) (templates.SarifOutput, error) {
	policyToViolationMap := getUniqueViolations(report.Violations)

	rules, err := constructRules(policyToViolationMap)
	if err != nil {
		return templates.SarifOutput{}, fmt.Errorf("constructRules: %v", err)
	}

	results := constructResults(report.Violations)

	sarifReport := templates.SarifOutput{
		Version: SARIF_VERSION,
		Schema:  SARIF_SCHEMA,
		Runs: []templates.Run{
			{
				Tool: templates.Tool{
					Driver: templates.Driver{
						Name:           IAC_TOOL_NAME,
						Version:        VERSION,
						InformationURI: IAC_TOOL_DOCUMENTATION_LINK,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return sarifReport, nil
}

func getUniqueViolations(violations []templates.Violation) map[string]templates.Violation {
	policyToViolationMap := make(map[string]templates.Violation)

	for _, violation := range violations {
		policyID := violation.PolicyID
		if _, ok := policyToViolationMap[policyID]; !ok {
			policyToViolationMap[policyID] = violation
		}
	}

	return policyToViolationMap
}

func constructRules(policyToViolationMap map[string]templates.Violation) ([]templates.Rule, error) {
	rules := []templates.Rule{}

	for policyID, violation := range policyToViolationMap {
		if !isSeverityValid(violation.Severity) {
			return nil, fmt.Errorf("isSeverityValid() invalid severity: %s ", violation.Severity)
		}

		rule := templates.Rule{
			ID: policyID,
			FullDescription: templates.FullDescription{
				Text: violation.ViolatedPolicy.Description,
			},
			Properties: templates.RuleProperties{
				Severity:            violation.Severity,
				PolicyType:          violation.ViolatedPolicy.ConstraintType,
				ComplianceStandard:  violation.ViolatedPolicy.ComplianceStandards,
				PolicySet:           violation.ViolatedPosture.PolicySet,
				Posture:             violation.ViolatedPosture.Posture,
				PostureRevisionID:   violation.ViolatedPosture.PostureRevisionID,
				PostureDeploymentID: violation.ViolatedPosture.PostureDeployment,
				Constraints:         violation.ViolatedPolicy.Constraint,
				NextSteps:           violation.NextSteps,
			},
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func constructResults(violations []templates.Violation) []templates.Result {
	results := []templates.Result{}

	for _, violation := range violations {
		result := templates.Result{
			RuleID: violation.PolicyID,
			Message: templates.Message{
				Text: fmt.Sprintf("Asset type: %s has a violation, next steps: %s", violation.ViolatedAsset.AssetType, violation.NextSteps),
			},
			Locations: []templates.Location{
				{
					LogicalLocations: []templates.LogicalLocations{
						{
							FullyQualifiedName: violation.AssetID,
						},
					},
				},
			},
			Properties: templates.ResultProperties{
				AssetID:   violation.AssetID,
				Asset:     violation.ViolatedAsset.Asset,
				AssetType: violation.ViolatedAsset.AssetType,
			},
		}
		results = append(results, result)
	}

	return results
}

func isSeverityValid(severity string) bool {
	return severity == "CRITICAL" || severity == "HIGH" || severity == "MEDIUM" || severity == "LOW" 
}
