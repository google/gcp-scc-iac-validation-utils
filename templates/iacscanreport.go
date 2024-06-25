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

// IACReportTemplate is the SCC IAC validation report template passed as an input.
type IACReportTemplate struct {
	Response Responses `json:"response,omitempty"`
}

type Responses struct {
	Name                string              `json:"name,omitempty"`
	CreateTime          string              `json:"createTime,omitempty"`
	UpdateTime          string              `json:"updateTime,omitempty"`
	IacValidationReport IACValidationReport `json:"iacValidationReport,omitempty"`
}

type IACValidationReport struct {
	Violations []Violation `json:"violations,omitempty"`
	Note       string      `json:"note,omitempty"`
}

type Violation struct {
	AssetID         string         `json:"assetId,omitempty"`
	PolicyID        string         `json:"policyId,omitempty"`
	ViolatedPosture PostureDetails `json:"violatedPosture,omitempty"`
	ViolatedPolicy  PolicyDetails  `json:"violatedPolicy,omitempty"`
	ViolatedAsset   AssetDetails   `json:"violatedAsset,omitempty"`
	Severity        string         `json:"severity,omitempty"`
	NextSteps       string         `json:"nextSteps,omitempty"`
}

type PostureDetails struct {
	PostureDeployment               string `json:"postureDeployment,omitempty"`
	PostureDeploymentTargetResource string `json:"postureDeploymentTargetResource,omitempty"`
	Posture                         string `json:"posture,omitempty"`
	PostureRevisionID               string `json:"postureRevisionId,omitempty"`
	PolicySet                       string `json:"policySet,omitempty"`
}

type PolicyDetails struct {
	Constraint          string   `json:"constraint,omitempty"`
	ConstraintType      string   `json:"constraintType,omitempty"`
	ComplianceStandards []string `json:"complianceStandards,omitempty"`
	Description         string   `json:"description,omitempty"`
}

type AssetDetails struct {
	Asset     string `json:"asset,omitempty"`
	AssetType string `json:"assetType,omitempty"`
}
