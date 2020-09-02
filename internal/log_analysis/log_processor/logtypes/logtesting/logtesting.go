package logtesting

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"text/template"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/omitempty"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

func RunTestsFromYAML(t *testing.T, resolve *logtypes.Registry, filename string) {
	t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Errorf("failed to open %q: %s", filename, err)
		return
	}
	dec := yaml.NewDecoder(f)
	dec.SetStrict(true)
	for {
		testCase := TestCase{
			Resolve: resolve,
		}
		if err := dec.Decode(&testCase); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("failed to read YAML test case: %s", err)
			return
		}
		t.Run(testCase.Name, testCase.Run)
	}
}

func RunTests(t *testing.T, tests ...TestCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.Name, tc.Run)
	}
}

type TestCase struct {
	Name    string             `json:"name" yaml:"name"`
	Input   string             `json:"input" yaml:"input"`
	Result  string             `json:"result" yaml:"result"`
	Results []string           `json:"results" yaml:"results"`
	LogType string             `json:"logType" yaml:"logType"`
	Resolve *logtypes.Registry `json:"-" yaml:"-"`
}

func (c *TestCase) Run(t *testing.T) {
	TestLogType(t, c.Resolve, c.LogType, c.Input, append([]string{c.Result}, c.Results...)...)
}

func TestLogType(t *testing.T, resolve *logtypes.Registry, logType, input string, expect ...string) {
	t.Helper()
	assert := require.New(t)
	if resolve == nil {
		resolve = registry.Default()
	}
	entry := resolve.Get(logType)
	assert.NotNil(entry)
	p, err := entry.NewParser(nil)
	assert.NoError(err, "failed to create log parser")
	results, err := p.ParseLog(input)
	assert.NoError(err)
	if len(expect) == 0 {
		require.Nil(t, results)
		return
	}
	schema := entry.Schema()
	indicators := pantherlog.FieldSetFromType(reflect.TypeOf(schema))
	assert.NotNil(results)
	assert.Equal(len(expect), len(results), "Invalid number of patherlog results produced by parser")
	for i, result := range results {
		expect := expect[i]
		expect = mustRenderExpect(expect, logType)
		TestResult(t, expect, result, indicators...)
	}
}

func TestParser(t *testing.T, p parsers.Interface, input string, expect ...string) {
	t.Helper()
	results, err := p.ParseLog(input)
	require.NoError(t, err)
	if len(expect) == 0 {
		require.Nil(t, results)
		return
	}
	require.NotNil(t, results)
	require.Equal(t, len(expect), len(results), "Invalid number of patherlog results produced by parser")
	for i, result := range results {
		expect := expect[i]
		TestResult(t, expect, result)
	}
}

func JSON() jsoniter.API {
	api := jsoniter.Config{
		EscapeHTML:             true,
		SortMapKeys:            true,
		ValidateJsonRawMessage: true,
	}.Froze()
	api.RegisterExtension(omitempty.New("json"))
	//api.RegisterExtension(&tcodec.Extension{})
	return api
}

// Checks that `actual` is a parser result matching `expect`
// If expect.RowID is empty it checks if actual has non-empty RowID
// If expect.EventTime is zero it checks if actual.EventTime equals actual.ParseTime
// If expect.ParseTime is zero it checks if actual.ParseTime is non-zero
// Otherwise equality is checked strictly
func TestResult(t *testing.T, expect string, actual *pantherlog.Result, indicators ...pantherlog.FieldID) {
	t.Helper()
	logType := jsoniter.Get([]byte(expect), pantherlog.FieldLogTypeJSON).ToString()
	require.Equal(t, logType, actual.PantherLogType)
	expectResult := pantherlog.Result{}
	if indicators == nil {
		indicators = pantherlog.FieldSetFromJSON([]byte(expect))
	}
	require.NoError(t, unmarshalResultJSON([]byte(expect), &expectResult, indicators))
	//require.Equal(t, -1, bytes.IndexByte(actual.JSON, '\n'), "Result JSON contains newlines")
	var expectAny map[string]interface{}
	require.NoError(t, jsoniter.UnmarshalFromString(expect, &expectAny))
	var actualAny map[string]interface{}
	data, err := JSON().Marshal(actual)
	require.NoError(t, err)
	require.NoError(t, jsoniter.Unmarshal(data, &actualAny))
	if expectResult.PantherParseTime.IsZero() {
		require.False(t, actual.PantherParseTime.IsZero(), "zero parse time")
	} else {
		EqualTimestamp(t, expectResult.PantherParseTime, actual.PantherParseTime, "invalid parse time")
	}
	if expectResult.PantherEventTime.IsZero() {
		EqualTimestamp(t, actual.PantherParseTime, actual.PantherEventTime, "event time not equal to parse time")
	} else {
		EqualTimestamp(t, expectResult.PantherEventTime, actual.PantherEventTime, "invalid event time")
	}
	if len(expectResult.PantherRowID) == 0 {
		require.NotEmpty(t, actual.PantherRowID)
	} else {
		require.Equal(t, expectResult.PantherRowID, actual.PantherRowID)
	}
	// The following dance ensures that produced JSON matches values from `actual` result

	require.Equal(t, actual.PantherEventTime.UTC().Format(time.RFC3339Nano), actualAny["p_event_time"], "Invalid JSON event time")
	require.Equal(t, actual.PantherParseTime.UTC().Format(time.RFC3339Nano), actualAny["p_parse_time"], "Invalid JSON parse time")
	require.Equal(t, actual.PantherRowID, actualAny["p_row_id"], "Invalid JSON row id")
	// Since these values are checked to be valid we assign them to expect to check the rest of the JSON values
	expectAny["p_event_time"] = actualAny["p_event_time"]
	expectAny["p_parse_time"] = actualAny["p_parse_time"]
	expectAny["p_row_id"] = actualAny["p_row_id"]
	// By now expect JSON and actual JSON must be equal
	expectJSON, err := jsoniter.MarshalToString(expectAny)
	require.NoError(t, err)
	actualJSON, err := jsoniter.MarshalToString(actualAny)
	require.NoError(t, err)
	require.JSONEq(t, expectJSON, actualJSON)
}

func EqualTimestamp(t *testing.T, expect, actual time.Time, msgAndArgs ...interface{}) {
	t.Helper()
	require.False(t, actual.IsZero(), "zero timestamp")
	require.Equal(t, expect.UTC().Format(time.RFC3339Nano), actual.UTC().Format(time.RFC3339Nano), msgAndArgs...)
}

// unmarshalResultJSON unmarshals a result from JSON
// The parsing is inefficient. It's purpose is to be used in tests to verify output results.
func unmarshalResultJSON(data []byte, r *pantherlog.Result, indicators pantherlog.FieldSet) error {
	tmp := struct {
		LogType     string      `json:"p_log_type"`
		EventTime   tcodec.Time `json:"p_event_time" tcodec:"rfc3339"`
		ParseTime   tcodec.Time `json:"p_parse_time" tcodec:"rfc3339"`
		RowID       string      `json:"p_row_id"`
		SourceID    string      `json:"p_source_id"`
		SourceLabel string      `json:"p_source_label"`
	}{}
	if err := jsoniter.Unmarshal(data, &tmp); err != nil {
		return err
	}
	values := pantherlog.BlankValueBuffer()
	for _, kind := range indicators {
		fieldName := pantherlog.FieldNameJSON(kind)
		any := jsoniter.Get(data, fieldName)
		if any == nil || any.ValueType() == jsoniter.InvalidValue {
			continue
		}
		var v []string
		any.ToVal(&v)
		if v != nil {
			values.WriteValues(kind, v...)
		}
	}
	*r = pantherlog.Result{
		CoreFields: pantherlog.CoreFields{
			PantherLogType:     tmp.LogType,
			PantherRowID:       tmp.RowID,
			PantherEventTime:   tmp.EventTime,
			PantherParseTime:   tmp.ParseTime,
			PantherSourceID:    tmp.SourceID,
			PantherSourceLabel: tmp.SourceLabel,
		},
	}
	values.WriteValuesTo(r)
	values.Recycle()
	return nil
}

func mustRenderExpect(expect, logType string) string {
	tpl := template.Must(template.New(logType).Parse(expect))
	s := strings.Builder{}
	data := &struct {
		LogType string
	}{
		LogType: logType,
	}
	if err := tpl.Execute(&s, &data); err != nil {
		panic(err)
	}

	return s.String()
}
