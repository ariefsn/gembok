package helper

import (
	"bytes"
	"encoding/json"
	"io"
)

func ToJsonBody(v interface{}) (*bytes.Buffer, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(b), nil
}

func FromResponseBody[T any](body io.ReadCloser) (T, error) {
	var target T
	err := json.NewDecoder(body).Decode(&target)

	if err != nil {
		return target, err
	}

	return target, nil
}

func FromJson[T any](from interface{}) (T, error) {
	var to T

	data, err := json.Marshal(from)

	if err != nil {
		return to, err
	}

	err = json.Unmarshal(data, &to)

	if err != nil {
		return to, err
	}

	return to, nil
}

func FromBytes[T any](from []byte) (T, error) {
	var to T

	err := json.Unmarshal(from, &to)

	if err != nil {
		return to, err
	}

	return to, nil
}

func ToBytes(from interface{}) []byte {
	b, _ := json.Marshal(from)
	return b
}

func ToPtr[T any](data T) *T {
	return &data
}
