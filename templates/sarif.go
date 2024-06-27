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

package templates

// SarifOutput is the struct for SARIF template. It only contains field
// relavent for converting IaC scc scan report to SARIF report.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
type SarifOutput struct {
	Version string `json:"version,omitempty"`
	Schema  string `json:"$schema,omitempty"`
	Runs    []Run  `json:"runs,omitempty"`
}

type Run struct {
	Tool    Tool     `json:"tool,omitempty"`
	Results []Result `json:"results,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver,omitempty"`
}

type Driver struct {
	Name           string `json:"name,omitempty"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID              string          `json:"id,omitempty"`
	FullDescription FullDescription `json:"fullDescription"`
	Properties      RuleProperties  `json:"properties,omitempty"`
}

type FullDescription struct {
	Text string `json:"text"`
}

type RuleProperties struct {
	Severity            string   `json:"severity,omitempty"`
	PolicyType          string   `json:"policyType,omitempty"`
	ComplianceStandard  []string `json:"complianceStandard,omitempty"`
	PolicySet           string   `json:"policySet,omitempty"`
	Posture             string   `json:"posture,omitempty"`
	PostureRevisionID   string   `json:"postureRevisionId,omitempty"`
	PostureDeploymentID string   `json:"postureDeploymentId,omitempty"`
	Constraints         string   `json:"constraints,omitempty"`
	NextSteps           string   `json:"nextSteps,omitempty"`
}

type Result struct {
	RuleID     string           `json:"ruleId,omitempty"`
	Message    Message          `json:"message,omitempty"`
	Locations  []Location       `json:"locations,omitempty"`
	Properties ResultProperties `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text,omitempty"`
}

type Location struct {
	LogicalLocations []LogicalLocations `json:"logicalLocations,omitempty"`
}

type LogicalLocations struct {
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

type ResultProperties struct {
	AssetID   string `json:"assetId,omitempty"`
	AssetType string `json:"assetType,omitempty"`
	Asset     string `json:"asset,omitempty"`
}
