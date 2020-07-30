package timestamp

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
	"math"
	"strconv"
	"time"
)

// These objects are used to read timestamps and ensure a consistent JSON output for timestamps.

// NOTE: prefix the name of all objects with Timestamp so schema generation can automatically understand these.
// NOTE: the suffix of the names is meant to reflect the time format being read (unmarshal)

// We want our output JSON timestamps to be: YYYY-MM-DD HH:MM:SS.fffffffff
// https://aws.amazon.com/premiumsupport/knowledge-center/query-table-athena-timestamp-empty/
const (
	jsonMarshalLayout     = `"2006-01-02 15:04:05.000000000"`
	jsonMarshalLayoutSize = len(jsonMarshalLayout)

	ansicWithTZUnmarshalLayout = `"Mon Jan 2 15:04:05 2006 MST"` // similar to time.ANSIC but with MST

	fluentdTimestampLayout = `"2006-01-02 15:04:05 -0700"`

	suricataTimestampLayout = `"2006-01-02T15:04:05.999999999Z0700"`

	//08 Jul 2020 09:00 GMT
	laceworkTimestampLayout = `"02 Jan 2006 15:04 MST"`
)

// use these functions to parse all incoming dates to ensure UTC consistency
func Parse(layout, value string) (RFC3339, error) {
	t, err := time.Parse(layout, value)
	return (RFC3339)(t.UTC()), err
}

func Unix(sec int64, nsec int64) RFC3339 {
	return (RFC3339)(time.Unix(sec, nsec).UTC())
}

func Now() RFC3339 {
	return (RFC3339)(time.Now().UTC())
}

type RFC3339 time.Time

func (ts *RFC3339) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *RFC3339) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *RFC3339) UnmarshalJSON(jsonBytes []byte) (err error) {
	if err = (*time.Time)(ts).UnmarshalJSON(jsonBytes); err == nil {
		return
	}
	if isGlueTimestampJSON(jsonBytes) && unmarshalGlueJSON(jsonBytes, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}

// In order to be able to re-parse panther log events to log event structs we need to detect if the
// timestamp is formatted using the jsonMarshalLayout.
// NOTE: This function is inlined and avoids bounds checks. The performance impact is practically zero.
func isGlueTimestampJSON(data []byte) bool {
	const dateTimeSeparatorOffset = 11
	return len(data) == jsonMarshalLayoutSize && data[dateTimeSeparatorOffset] == ' '
}

func unmarshalGlueJSON(data []byte, timestamp *time.Time) error {
	tm, err := time.Parse(jsonMarshalLayout, string(data))
	if err != nil {
		return err
	}
	*timestamp = tm
	return nil
}

// Like time.ANSIC but with MST
type ANSICwithTZ time.Time

func (ts *ANSICwithTZ) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *ANSICwithTZ) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *ANSICwithTZ) UnmarshalJSON(text []byte) (err error) {
	t, err := time.Parse(ansicWithTZUnmarshalLayout, string(text))
	if err == nil {
		*ts = (ANSICwithTZ)(t.UTC())
		return
	}
	if isGlueTimestampJSON(text) && unmarshalGlueJSON(text, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}

// UnixMillisecond for JSON timestamps that are in unix epoch milliseconds
type UnixMillisecond time.Time

func (ts *UnixMillisecond) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *UnixMillisecond) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *UnixMillisecond) UnmarshalJSON(jsonBytes []byte) (err error) {
	value, err := strconv.ParseInt(string(jsonBytes), 10, 64)
	if err == nil {
		t := time.Unix(0, value*time.Millisecond.Nanoseconds())
		*ts = (UnixMillisecond)(t.UTC())
		return
	}
	if isGlueTimestampJSON(jsonBytes) && unmarshalGlueJSON(jsonBytes, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}

type FluentdTimestamp time.Time

func (ts *FluentdTimestamp) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *FluentdTimestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *FluentdTimestamp) UnmarshalJSON(jsonBytes []byte) (err error) {
	t, err := time.Parse(fluentdTimestampLayout, string(jsonBytes))
	if err == nil {
		*ts = (FluentdTimestamp)(t.UTC())
		return
	}
	if isGlueTimestampJSON(jsonBytes) && unmarshalGlueJSON(jsonBytes, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}

type SuricataTimestamp time.Time

func (ts *SuricataTimestamp) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *SuricataTimestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *SuricataTimestamp) UnmarshalJSON(jsonBytes []byte) (err error) {
	t, err := time.Parse(suricataTimestampLayout, string(jsonBytes))
	if err == nil {
		*ts = (SuricataTimestamp)(t.UTC())
		return
	}
	if isGlueTimestampJSON(jsonBytes) && unmarshalGlueJSON(jsonBytes, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}

// UnixFloat for JSON timestamps that are in unix seconds + fractions of a second
type UnixFloat time.Time

func (ts *UnixFloat) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}
func (ts *UnixFloat) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}
func (ts *UnixFloat) UnmarshalJSON(jsonBytes []byte) (err error) {
	f, err := strconv.ParseFloat(string(jsonBytes), 64)
	if err == nil {
		intPart, fracPart := math.Modf(f)
		t := time.Unix(int64(intPart), int64(fracPart*1e9))
		*ts = (UnixFloat)(t.UTC())
		return
	}
	if isGlueTimestampJSON(jsonBytes) && unmarshalGlueJSON(jsonBytes, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}

type LaceworkTimestamp time.Time

func (ts *LaceworkTimestamp) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *LaceworkTimestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(laceworkTimestampLayout)), nil // ensure UTC
}

func (ts *LaceworkTimestamp) UnmarshalJSON(jsonBytes []byte) (err error) {
	t, err := time.Parse(laceworkTimestampLayout, string(jsonBytes))
	if err == nil {
		*ts = (LaceworkTimestamp)(t.UTC())
		return
	}
	if isGlueTimestampJSON(jsonBytes) && unmarshalGlueJSON(jsonBytes, (*time.Time)(ts)) == nil {
		return nil
	}
	return
}
