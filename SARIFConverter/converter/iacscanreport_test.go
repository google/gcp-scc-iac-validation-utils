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

package converter

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/google/gcp-scc-iac-validation-utils/templates"
)

func TestGenerateReport(t *testing.T) {
	tests := []struct {
		name                string
		validationReport templates.IACValidationReport
		wantError       bool
		wantOutput      templates.SarifOutput
	}{
		{
			name:                "ValidReport_Succeeds",
			validationReport: IACValidationValidReport,
			wantOutput:      IACValidSarifOutput,
			wantError:       false,
		},
		{
			name:                "InvalidSeverityReport_Failure",
			validationReport: IACValidationReportWithInvalidSeverity,
			wantOutput:      templates.SarifOutput{},
			wantError:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualOutput, err := FromIACScanReport(test.validationReport)

			if (err != nil) != test.wantError {
				t.Errorf("Expected error: %v, got: %v", test.wantError, err)
			}

			if diff := cmp.Diff(test.wantOutput, actualOutput); diff != "" {
				t.Errorf("Expected output (+got, -want): %v", diff)
			}
		})
	}
}

func TestGetUniqueViolations(t *testing.T) {
	testCases := []struct {
		name     string
		input    []templates.Violation
		expected map[string]templates.Violation
	}{
		{
			name:     "NoViolations",
			input:    []templates.Violation{},
			expected: map[string]templates.Violation{},
		},
		{
			name: "MultipleUniqueViolations",
			input: []templates.Violation{
				{PolicyID: "policy1", Severity: "violation1"},
				{PolicyID: "policy2", Severity: "violation2"},
				{PolicyID: "policy3", Severity: "violation3"},
			},
			expected: map[string]templates.Violation{
				"policy1": {PolicyID: "policy1", Severity: "violation1"},
				"policy2": {PolicyID: "policy2", Severity: "violation2"},
				"policy3": {PolicyID: "policy3", Severity: "violation3"},
			},
		},
		{
			name: "DuplicateViolations",
			input: []templates.Violation{
				{PolicyID: "policy1", Severity: "violation1"},
				{PolicyID: "policy2", Severity: "violation2"},
				{PolicyID: "policy1", Severity: "violation1"},
			},
			expected: map[string]templates.Violation{
				"policy1": {PolicyID: "policy1", Severity: "violation1"},
				"policy2": {PolicyID: "policy2", Severity: "violation2"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getUniqueViolations(tc.input)

			if diff := cmp.Diff(tc.expected, result); diff != "" {
				t.Errorf("Expected %v, (-want, +got)", diff)
			}
		})
	}
}

func TestConstructRules(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]templates.Violation
		expected []templates.Rule
	}{
		{
			name:     "EmptyInput",
			input:    map[string]templates.Violation{},
			expected: []templates.Rule{},
		},
		{
			name: "MultipleViolations",
			input: map[string]templates.Violation{
				"policy1": {
					PolicyID:        "policy1",
					Severity:        "HIGH",
					ViolatedPolicy:  templates.PolicyDetails{Description: "Description 1", ConstraintType: "Type 1", ComplianceStandards: []string{"Standard 1"}},
					ViolatedPosture: templates.PostureDetails{PolicySet: "Set 1", Posture: "Posture 1", PostureRevisionID: "Rev 1", PostureDeployment: "Dep 1"},
					NextSteps:       "Next steps 1",
				},
				"policy2": {
					PolicyID:       "policy2",
					Severity:       "MEDIUM",
					ViolatedPolicy: templates.PolicyDetails{Description: "Description 2", ConstraintType: "Type 2"},
					NextSteps:      "Next steps 2",
				},
			},
			expected: []templates.Rule{
				{
					ID:              "policy2",
					FullDescription: templates.FullDescription{Text: "Description 2"},
					Properties: templates.RuleProperties{
						Severity:   "MEDIUM",
						PolicyType: "Type 2",
						NextSteps:  "Next steps 2",
					},
				},
				{
					ID:              "policy1",
					FullDescription: templates.FullDescription{Text: "Description 1"},
					Properties: templates.RuleProperties{
						Severity:            "HIGH",
						PolicyType:          "Type 1",
						ComplianceStandard:  []string{"Standard 1"},
						PolicySet:           "Set 1",
						Posture:             "Posture 1",
						PostureRevisionID:   "Rev 1",
						PostureDeploymentID: "Dep 1",
						NextSteps:           "Next steps 1",
					},
				},
			},
		},
		{
			name: "MissingFields",
			input: map[string]templates.Violation{
				"policy3": {
					PolicyID:        "policy3",
					Severity:        "LOW",
					ViolatedPolicy:  templates.PolicyDetails{},
					ViolatedPosture: templates.PostureDetails{},
					NextSteps:       "Next steps 3",
				},
			},
			expected: []templates.Rule{
				{
					ID: "policy3",
					Properties: templates.RuleProperties{
						Severity:  "LOW",
						NextSteps: "Next steps 3",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := constructRules(tc.input)
			if err != nil {
				t.Fatalf("constructRules(%v) failed: %v", tc.input, err)
			}

			if diff := cmp.Diff(tc.expected, result); diff != "" {
				t.Errorf("Expected %v, (-want, +got)", diff)
			}
		})
	}
}

func TestConstructResults(t *testing.T) {
	testCases := []struct {
		name     string
		input    []templates.Violation
		expected []templates.Result
	}{
		{
			name:     "EmptyInput",
			input:    []templates.Violation{},
			expected: []templates.Result{},
		},
		{
			name: "MissingFields",
			input: []templates.Violation{
				{
					PolicyID: "policy1",
					AssetID:  "asset1",
				},
			},
			expected: []templates.Result{
				{
					RuleID:  "policy1",
					Message: templates.Message{Text: "Asset type:  has a violation, next steps: "},
					Locations: []templates.Location{
						{
							LogicalLocations: []templates.LogicalLocations{
								{FullyQualifiedName: "asset1"},
							},
						},
					},
					Properties: templates.ResultProperties{
						AssetID: "asset1",
					},
				},
			},
		},
		{
			name: "MultipleViolations",
			input: []templates.Violation{
				{
					PolicyID:      "policy1",
					AssetID:       "asset1",
					NextSteps:     "next_steps1",
					ViolatedAsset: templates.AssetDetails{AssetType: "type1", Asset: "asset1"},
				},
				{
					PolicyID:      "policy2",
					AssetID:       "asset2",
					NextSteps:     "next_steps2",
					ViolatedAsset: templates.AssetDetails{AssetType: "type2", Asset: "asset2"},
				},
			},
			expected: []templates.Result{
				{
					RuleID:  "policy1",
					Message: templates.Message{Text: "Asset type: type1 has a violation, next steps: next_steps1"},
					Locations: []templates.Location{
						{
							LogicalLocations: []templates.LogicalLocations{
								{FullyQualifiedName: "asset1"},
							},
						},
					},
					Properties: templates.ResultProperties{
						AssetID:   "asset1",
						Asset:     "asset1",
						AssetType: "type1",
					},
				},
				{
					RuleID:  "policy2",
					Message: templates.Message{Text: "Asset type: type2 has a violation, next steps: next_steps2"},
					Locations: []templates.Location{
						{
							LogicalLocations: []templates.LogicalLocations{
								{FullyQualifiedName: "asset2"},
							},
						},
					},
					Properties: templates.ResultProperties{
						AssetID:   "asset2",
						Asset:     "asset2",
						AssetType: "type2",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := constructResults(tc.input)

			if diff := cmp.Diff(tc.expected, result); diff != "" {
				t.Errorf("Expected %v, (-want, +got)", diff)
			}
		})
	}
}
