package catalog

import "errors"

var (
	ErrNoMatch   = errors.New("no matching server")
	ErrAmbiguous = errors.New("ambiguous location")
	ErrInvalid   = errors.New("invalid catalog data")
)
