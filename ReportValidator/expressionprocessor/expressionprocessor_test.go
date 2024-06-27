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

package expressionprocessor

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProcessExpression(t *testing.T) {
	tests := []struct {
		name                   string
		expression             string
		expectedSeverityCounts map[string]int
		expectedOperator       string
		expectedError          bool
	}{
		{
			name:       "SingleSeverityInExpression_Succeeds",
			expression: "critical:2,operator:and",
			expectedSeverityCounts: map[string]int{
				"CRITICAL": 2,
			},
			expectedOperator: "AND",
			expectedError:    false,
		},
		{
			name:       "MultipleSeverityInExpression_Succeeds",
			expression: "critical:2,high:1,medium:3,operator:or",
			expectedSeverityCounts: map[string]int{
				"CRITICAL": 2,
				"HIGH":     1,
				"MEDIUM":   3,
			},
			expectedOperator: "OR",
			expectedError:    false,
		},
		{
			name:       "MixedCaseInExpression_Succeeds",
			expression: "CrItICal:2,HiGH:1,medium:3,oPERATOR:oR",
			expectedSeverityCounts: map[string]int{
				"CRITICAL": 2,
				"HIGH":     1,
				"MEDIUM":   3,
			},
			expectedOperator: "OR",
			expectedError:    false,
		},
		{
			name:                   "ExpressionWithNegativeValue_Failure",
			expression:             "high:-1,operator:or",
			expectedSeverityCounts: nil,
			expectedOperator:       "OR",
			expectedError:          true,
		},
		{
			name:                   "DuplicateOperatorPresent_Failure",
			expression:             "critical:2,operator:or,operator:and",
			expectedSeverityCounts: nil,
			expectedOperator:       "",
			expectedError:          true,
		},
		{
			name:                   "OperatorNotPresent_Failure",
			expression:             "critical:2,high:1,medium:3",
			expectedSeverityCounts: nil,
			expectedOperator:       "",
			expectedError:          true,
		},
		{
			name:                   "SeverityNotPresent_Failure",
			expression:             "operator:or",
			expectedSeverityCounts: nil,
			expectedOperator:       "",
			expectedError:          true,
		},
		{
			name:                   "DuplicateSeverityPresent_Failure",
			expression:             "critical:2,high:1,medium:3,medium:4,operator:or",
			expectedSeverityCounts: nil,
			expectedOperator:       "",
			expectedError:          true,
		},
		{
			name:                   "InvalidExpression_Failure",
			expression:             "critical:invalid,high:1,medium:3",
			expectedSeverityCounts: nil,
			expectedOperator:       "",
			expectedError:          true,
		},
		{
			name:       "ExpressionNotPassed_SetDefault",
			expression: "",
			expectedSeverityCounts: map[string]int{
				"CRITICAL": 1,
				"HIGH":     1,
				"MEDIUM":   1,
				"LOW":      1,
			},
			expectedOperator: "OR",
			expectedError:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			operator, severityCounts, err := ParseFailureExpression(test.expression)
			if (err != nil) != test.expectedError {
				t.Fatalf("Expected error: %v, got error %v", test.expectedError, err)
			}
			if diff := cmp.Diff(test.expectedSeverityCounts, severityCounts); diff != "" {
				t.Errorf("Expected severityCounts (+got, -want): %v", diff)
			}
			if err == nil && operator != test.expectedOperator {
				t.Errorf("Unexpected operator: expected %v, got %v", test.expectedOperator, operator)
			}
		})
	}
}

func TestValidateOperator(t *testing.T) {
	tests := []struct {
		name               string
		operator           string
		expressionOperator string
		expectedOperator   string
		wantError          bool
	}{
		{
			name:               "AndOperator_Succeeds",
			operator:           "",
			expressionOperator: "AND",
			expectedOperator:   "AND",
			wantError:          false,
		},
		{
			name:               "OrOperator_Succeeds",
			operator:           "",
			expressionOperator: "OR",
			expectedOperator:   "OR",
			wantError:          false,
		},
		{
			name:               "InvalidOperator_Failure",
			operator:           "",
			expressionOperator: "NOT",
			expectedOperator:   "",
			wantError:          true,
		},
		{
			name:               "OperatorAlreadySet_Failure",
			operator:           "AND",
			expressionOperator: "OR",
			expectedOperator:   "",
			wantError:          true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			operator, err := validateOperator(test.operator, test.expressionOperator)
			if (err != nil) != test.wantError {
				t.Errorf("Expected error: %v, got: %v", test.wantError, err)
			}

			if operator != test.expectedOperator {
				t.Errorf("Expected operator: %v, got: %v", test.expectedOperator, operator)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	tests := []struct {
		name          string
		severity      string
		severityCount int
		wantError     bool
	}{
		{
			name:          "ValidSeverity_Succeeds",
			severity:      "HIGH",
			severityCount: 1,
			wantError:     false,
		},
		{
			name:          "UndefinedSeverity_Error",
			severity:      "Undefined",
			severityCount: 1,
			wantError:     true,
		},
		{
			name:          "NegativeSeverityCount_Error",
			severity:      "CRITICAL",
			severityCount: -1,
			wantError:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateSeverity(test.severity, test.severityCount)
			if (err != nil) != test.wantError {
				t.Errorf("Expected error: %v, got: %v", test.wantError, err)
			}
		})
	}
}
