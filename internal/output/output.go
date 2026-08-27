package output

import (
	"encoding/json"
	"io"
)

const SchemaVersion = 1

type successEnvelope struct {
	SchemaVersion int  `json:"schema_version"`
	OK            bool `json:"ok"`
	Data          any  `json:"data"`
}

type errorEnvelope struct {
	SchemaVersion int         `json:"schema_version"`
	OK            bool        `json:"ok"`
	Error         errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func JSONSuccess(writer io.Writer, data any) error {
	return encode(writer, successEnvelope{SchemaVersion: SchemaVersion, OK: true, Data: data})
}

func JSONError(writer io.Writer, code, message string) error {
	return encode(writer, errorEnvelope{SchemaVersion: SchemaVersion, OK: false, Error: errorDetail{Code: code, Message: message}})
}

func encode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
