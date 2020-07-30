package parsers

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

type ResultStream interface {
	Next() (*Result, error)
}

type StreamResultsError interface {
	error
	Stream() ResultStream
}

func NewStreamResultsError(stream ResultStream) error {
	return &streamResultsError{
		stream: stream,
	}
}

type streamResultsError struct {
	stream ResultStream
}

func (*streamResultsError) Error() string {
	return "streaming results"
}
func (s *streamResultsError) Stream() ResultStream {
	return s.stream
}

func StreamResults(results ...*Result) ResultStream {
	return &sliceResultStream{
		results: results,
	}
}

type sliceResultStream struct {
	results []*Result
	index   int
}

func (s *sliceResultStream) Next() (*Result, error) {
	if i := s.index; 0 <= i && i < len(s.results) {
		r := s.results[i]
		s.index++
		return r, nil
	}
	// send results to GC
	s.results = nil
	return nil, nil
}
