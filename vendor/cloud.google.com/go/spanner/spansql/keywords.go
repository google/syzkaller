/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package spansql

import (
	"strings"
)

// IsKeyword reports whether the identifier is a reserved keyword.
func IsKeyword(id string) bool {
	return keywords[strings.ToUpper(id)]
}

// keywords is the set of reserved keywords.
// https://cloud.google.com/spanner/docs/lexical#reserved-keywords
var keywords = map[string]bool{
	"ALL":                  true,
	"AND":                  true,
	"ANY":                  true,
	"ARRAY":                true,
	"AS":                   true,
	"ASC":                  true,
	"ASSERT_ROWS_MODIFIED": true,
	"AT":                   true,
	"BETWEEN":              true,
	"BY":                   true,
	"CASE":                 true,
	"CAST":                 true,
	"COLLATE":              true,
	"CONTAINS":             true,
	"CREATE":               true,
	"CROSS":                true,
	"CUBE":                 true,
	"CURRENT":              true,
	"DEFAULT":              true,
	"DEFINE":               true,
	"DESC":                 true,
	"DISTINCT":             true,
	"ELSE":                 true,
	"END":                  true,
	"ENUM":                 true,
	"ESCAPE":               true,
	"EXCEPT":               true,
	"EXCLUDE":              true,
	"EXISTS":               true,
	"EXTRACT":              true,
	"FALSE":                true,
	"FETCH":                true,
	"FOLLOWING":            true,
	"FOR":                  true,
	"FROM":                 true,
	"FULL":                 true,
	"GROUP":                true,
	"GROUPING":             true,
	"GROUPS":               true,
	"HASH":                 true,
	"HAVING":               true,
	"IF":                   true,
	"IGNORE":               true,
	"IN":                   true,
	"INNER":                true,
	"INTERSECT":            true,
	"INTERVAL":             true,
	"INTO":                 true,
	"IS":                   true,
	"JOIN":                 true,
	"LATERAL":              true,
	"LEFT":                 true,
	"LIKE":                 true,
	"LIMIT":                true,
	"LOOKUP":               true,
	"MERGE":                true,
	"NATURAL":              true,
	"NEW":                  true,
	"NO":                   true,
	"NOT":                  true,
	"NULL":                 true,
	"NULLS":                true,
	"OF":                   true,
	"ON":                   true,
	"OR":                   true,
	"ORDER":                true,
	"OUTER":                true,
	"OVER":                 true,
	"PARTITION":            true,
	"PRECEDING":            true,
	"PROTO":                true,
	"RANGE":                true,
	"RECURSIVE":            true,
	"RESPECT":              true,
	"RIGHT":                true,
	"ROLLUP":               true,
	"ROWS":                 true,
	"SELECT":               true,
	"SET":                  true,
	"SOME":                 true,
	"STRUCT":               true,
	"TABLESAMPLE":          true,
	"THEN":                 true,
	"TO":                   true,
	"TREAT":                true,
	"TRUE":                 true,
	"UNBOUNDED":            true,
	"UNION":                true,
	"UNNEST":               true,
	"USING":                true,
	"WHEN":                 true,
	"WHERE":                true,
	"WINDOW":               true,
	"WITH":                 true,
	"WITHIN":               true,
}

// funcs is the set of reserved keywords that are functions.
// https://cloud.google.com/spanner/docs/functions-and-operators
var funcs = make(map[string]bool)
var funcArgParsers = make(map[string]func(*parser) (Expr, *parseError))
var aggregateFuncs = make(map[string]bool)

func init() {
	for _, f := range funcNames {
		funcs[f] = true
	}
	for _, f := range aggregateFuncNames {
		funcs[f] = true
		aggregateFuncs[f] = true
	}
	// Special case for CAST, SAFE_CAST and EXTRACT
	funcArgParsers["CAST"] = typedArgParser
	funcArgParsers["SAFE_CAST"] = typedArgParser
	funcArgParsers["EXTRACT"] = extractArgParser
	// Spacial case of INTERVAL arg for DATE_ADD, DATE_SUB, GENERATE_DATE_ARRAY
	funcArgParsers["DATE_ADD"] = dateIntervalArgParser
	funcArgParsers["DATE_SUB"] = dateIntervalArgParser
	funcArgParsers["GENERATE_DATE_ARRAY"] = dateIntervalArgParser
	// Spacial case of INTERVAL arg for TIMESTAMP_ADD, TIMESTAMP_SUB
	funcArgParsers["TIMESTAMP_ADD"] = timestampIntervalArgParser
	funcArgParsers["TIMESTAMP_SUB"] = timestampIntervalArgParser
	// Special case of SEQUENCE arg for GET_NEXT_SEQUENCE_VALUE, GET_INTERNAL_SEQUENCE_STATE
	funcArgParsers["GET_NEXT_SEQUENCE_VALUE"] = sequenceArgParser
	funcArgParsers["GET_INTERNAL_SEQUENCE_STATE"] = sequenceArgParser
}

var funcNames = []string{
	// TODO: many more

	// Cast functions.
	"CAST",
	"SAFE_CAST",

	// Mathematical functions.
	"ABS",
	"ACOS",
	"ACOSH",
	"ASIN",
	"ASINH",
	"ATAN",
	"ATAN2",
	"ATANH",
	"CEIL",
	"CEILING",
	"COS",
	"COSH",
	"DIV",
	"EXP",
	"FLOOR",
	"GREATEST",
	"IEEE_DIVIDE",
	"IS_INF",
	"IS_NAN",
	"LEAST",
	"LN",
	"LOG",
	"LOG10",
	"MOD",
	"POW",
	"POWER",
	"ROUND",
	"SAFE_ADD",
	"SAFE_DIVIDE",
	"SAFE_MULTIPLY",
	"SAFE_NEGATE",
	"SAFE_SUBTRACT",
	"SIGN",
	"SIN",
	"SINH",
	"SQRT",
	"TAN",
	"TANH",
	"TRUNC",

	// Hash functions.
	"FARM_FINGERPRINT",
	"SHA1",
	"SHA256", "SHA512",

	// String functions.
	"BYTE_LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH",
	"CODE_POINTS_TO_BYTES", "CODE_POINTS_TO_STRING",
	"CONCAT",
	"ENDS_WITH",
	"FORMAT",
	"FROM_BASE32", "FROM_BASE64", "FROM_HEX",
	"LENGTH",
	"LOWER",
	"LPAD",
	"LTRIM",
	"REGEXP_CONTAINS", "REGEXP_EXTRACT", "REGEXP_EXTRACT_ALL", "REGEXP_REPLACE",
	"REPEAT",
	"REPLACE",
	"REVERSE",
	"RPAD",
	"RTRIM",
	"SAFE_CONVERT_BYTES_TO_STRING",
	"SPLIT",
	"STARTS_WITH",
	"STRPOS",
	"SUBSTR",
	"TO_BASE32", "TO_BASE64", "TO_CODE_POINTS", "TO_HEX",
	"TRIM",
	"UPPER",

	// Array functions.
	"ARRAY",
	"ARRAY_CONCAT",
	"ARRAY_FIRST", "ARRAY_INCLUDES", "ARRAY_INCLUDES_ALL", "ARRAY_INCLUDES_ANY", "ARRAY_LAST",
	"ARRAY_LENGTH",
	"ARRAY_MAX", "ARRAY_MIN", "ARRAY_REVERSE", "ARRAY_SLICE", "ARRAY_TRANSFORM",
	"ARRAY_TO_STRING",
	"GENERATE_ARRAY", "GENERATE_DATE_ARRAY",
	"OFFSET", "ORDINAL",
	"ARRAY_REVERSE",
	"ARRAY_IS_DISTINCT",
	"SAFE_OFFSET", "SAFE_ORDINAL",

	// Date functions.
	"CURRENT_DATE",
	"EXTRACT",
	"DATE",
	"DATE_ADD",
	"DATE_SUB",
	"DATE_DIFF",
	"DATE_TRUNC",
	"DATE_FROM_UNIX_DATE",
	"FORMAT_DATE",
	"PARSE_DATE",
	"UNIX_DATE",

	// Timestamp functions.
	"CURRENT_TIMESTAMP",
	"STRING",
	"TIMESTAMP",
	"TIMESTAMP_ADD",
	"TIMESTAMP_SUB",
	"TIMESTAMP_DIFF",
	"TIMESTAMP_TRUNC",
	"FORMAT_TIMESTAMP",
	"PARSE_TIMESTAMP",
	"TIMESTAMP_SECONDS",
	"TIMESTAMP_MILLIS",
	"TIMESTAMP_MICROS",
	"UNIX_SECONDS",
	"UNIX_MILLIS",
	"UNIX_MICROS",
	"PENDING_COMMIT_TIMESTAMP",

	// JSON functions.
	"JSON_QUERY",
	"JSON_VALUE",
	"JSON_QUERY_ARRAY",
	"JSON_VALUE_ARRAY",

	// Bit functions.
	"BIT_COUNT",
	"BIT_REVERSE",

	// Sequence functions.
	"GET_NEXT_SEQUENCE_VALUE",
	"GET_INTERNAL_SEQUENCE_STATE",

	// Utility functions.
	"GENERATE_UUID",
}

var aggregateFuncNames = []string{
	// Aggregate functions.
	"ANY_VALUE",
	"ARRAY_AGG",
	"ARRAY_CONCAT_AGG",
	"AVG",
	"BIT_AND",
	"BIT_OR",
	"BIT_XOR",
	"COUNT",
	"COUNTIF",
	"LOGICAL_AND",
	"LOGICAL_OR",
	"MAX",
	"MIN",
	"STRING_AGG",
	"SUM",

	// Statistical aggregate functions.
	"STDDEV",
	"STDDEV_SAMP",
	"VAR_SAMP",
	"VARIANCE",
}
