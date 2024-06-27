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
	"github.com/google/gcp-scc-iac-validation-utils/templates"
)

var IACValidationValidReport = templates.IACValidationReport{
	Violations: []templates.Violation{
		{
			AssetID:  "Asset 1",
			PolicyID: "P1",
			Severity: "HIGH",
			ViolatedPolicy: templates.PolicyDetails{
				Description:         "High-level violation message",
				ConstraintType:      "Type 1",
				ComplianceStandards: []string{"Standard 1"},
			},
			NextSteps: "Next steps 1",
			ViolatedPosture: templates.PostureDetails{
				PolicySet:         "Set 1",
				Posture:           "Posture 1",
				PostureRevisionID: "Rev 1",
				PostureDeployment: "Dep 1",
			},
			ViolatedAsset: templates.AssetDetails{
				AssetType: "Type 1",
				Asset:     "Asset 1",
			},
		},
	},
}

var IACValidationReportWithInvalidSeverity = templates.IACValidationReport{
	Violations: []templates.Violation{
		{
			AssetID:  "Asset 1",
			PolicyID: "P1",
			Severity: "INVALID_SEVERITY",
			ViolatedPolicy: templates.PolicyDetails{
				Description:         "High-level violation message",
				ConstraintType:      "Type 1",
				ComplianceStandards: []string{"Standard 1"},
			},
			NextSteps: "Next steps 1",
			ViolatedPosture: templates.PostureDetails{
				PolicySet:         "Set 1",
				Posture:           "Posture 1",
				PostureRevisionID: "Rev 1",
				PostureDeployment: "Dep 1",
			},
			ViolatedAsset: templates.AssetDetails{
				AssetType: "Type 1",
				Asset:     "Asset 1",
			},
		},
	},
}

var IACValidSarifOutput = templates.SarifOutput{
	Version: SARIF_VERSION,
	Schema:  SARIF_SCHEMA,
	Runs: []templates.Run{
		{
			Tool: templates.Tool{
				Driver: templates.Driver{
					Name:           IAC_TOOL_NAME,
					Version:        "1.0.0",
					InformationURI: IAC_TOOL_DOCUMENTATION_LINK,
					Rules: []templates.Rule{
						{
							ID:              "P1",
							FullDescription: templates.FullDescription{Text: "High-level violation message"},
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
			},
			Results: []templates.Result{
				{
					RuleID:  "P1",
					Message: templates.Message{Text: "Asset type: Type 1 has a violation, next steps: Next steps 1"},
					Locations: []templates.Location{
						{
							LogicalLocations: []templates.LogicalLocations{
								{FullyQualifiedName: "Asset 1"},
							},
						},
					},
					Properties: templates.ResultProperties{
						AssetID:   "Asset 1",
						Asset:     "Asset 1",
						AssetType: "Type 1",
					},
				},
			},
		},
	},
}
