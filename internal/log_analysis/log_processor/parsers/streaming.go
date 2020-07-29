package parsers

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
