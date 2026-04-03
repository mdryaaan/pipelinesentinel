package llm

import "errors"

// ErrMalformed marks a response that could not be parsed into the schema.
//
// It is separated from transport errors on purpose: a malformed response is
// worth one retry with a repair instruction, while a refused connection is not
// going to be fixed by asking the model more firmly.
var ErrMalformed = errors.New("malformed model response")

func errorsIs(err, target error) bool { return errors.Is(err, target) }
