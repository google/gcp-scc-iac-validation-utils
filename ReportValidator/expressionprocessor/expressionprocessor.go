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

// package expressionprocessor validates the input expression and extracts
// operator and threshold values.
package expressionprocessor

import (
	"fmt"
	"strconv"
	"strings"
)

func ParseFailureExpression(expression string) (string, map[string]int, error) {
	pairs := strings.Split(expression, ",")

	// If user expression is empty then return default threshold limits.
	if expression == "" {
		return "OR", map[string]int{"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}, nil
	}

	var operator = ""
	var userViolationCount = make(map[string]int)

	for _, pair := range pairs {
		parts := strings.Split(pair, ":")
		key := strings.ToUpper(parts[0])

		// Checks if operator passed by user expression valid and not repeated.
		if key == "OPERATOR" {
			op, err := validateOperator(operator, strings.ToUpper(parts[1]))
			if err != nil {
				return "", nil, err
			}
			operator = op
			continue
		}

		// Checks if a severity is repeated in user passed expression.
		if _, ok := userViolationCount[key]; ok {
			return "", nil, fmt.Errorf("duplicate severity found: %v", key)
		}

		value, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", nil, fmt.Errorf("error converting value to integer: %v", err)
		}

		if err := validateSeverity(key, value); err != nil {
			return "", nil, err
		}

		userViolationCount[key] = value
	}

	if len(userViolationCount) == 0 {
		return "", nil, fmt.Errorf("no voilaition parameter found in expression")
	}

	if operator == "" {
		return "", nil, fmt.Errorf("no operator found in expression")
	}

	return operator, userViolationCount, nil
}

func validateOperator(finalOperator, expressionOperator string) (string, error) {
	if finalOperator != "" {
		return "", fmt.Errorf("more than one operator found in the expression %v", finalOperator)
	}

	if expressionOperator == "AND" || expressionOperator == "OR" {
		return expressionOperator, nil
	}

	return "", fmt.Errorf("invalid operator: %v", finalOperator)
}

func validateSeverity(severity string, severityCount int) error {
	if severityCount < 0 {
		return fmt.Errorf("validation expression can not have negative values")
	}

	if severity == "CRITICAL" || severity == "HIGH" || severity == "MEDIUM" || severity == "LOW" {
		return nil
	}

	return fmt.Errorf("invalid severity expression: %s", severity)
}
