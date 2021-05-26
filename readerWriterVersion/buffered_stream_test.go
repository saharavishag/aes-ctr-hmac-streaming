package dump

import (
	"io"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestWriteRead(t *testing.T) {
	log := zaptest.NewLogger(t)
	bs := newBS(log)

	expectedValue := getExpectedValue(100)

	go func() {
		bs.Write([]byte(expectedValue))
		bs.flush()
	}()

	b := make([]byte, 10)
	var res []byte
	for {
		_, err := bs.Read(b)
		if err == io.EOF {
			break
		}
		res = append(res, b...)
	}
	if expectedValue != string(res) {
		t.Errorf("invalid value, expected: %s, got: %s", expectedValue, string(res))
	}

}
