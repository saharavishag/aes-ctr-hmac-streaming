package dump

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"dip-csp/pkg/config"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestEncryptDecrypt(t *testing.T) {
	log := zaptest.NewLogger(t)
	cfg := &config.Setting{
		FileCTRHmacKey:       getRandomEncryptionKey(),
		FileCTREncryptionKey: getRandomEncryptionKey(),
		EncryptKeyVersion:    "v1",
	}
	inputFile, err := ioutil.TempFile("", "encTestInTmpFile")
	if err != nil {
		t.Errorf("Failed to create input temp file for encryption test")
	}
	defer os.Remove(inputFile.Name())
	// some random nonesense
	expectedValue := getExpectedValue(100)
	w := bufio.NewWriter(inputFile)
	_, err = w.WriteString(expectedValue)
	if err != nil {
		t.Errorf("Failed to write to input temp file for encryption test")
	}
	w.Flush()

	input, err := os.Open(inputFile.Name())
	if err != nil {
		t.Errorf("Failed to load input temp file for encryption test")
	}
	outputFile, err := ioutil.TempFile("", "encTestOutTmpFile")
	if err != nil {
		t.Errorf("Failed to create output temp file for encryption test")
	}
	defer os.Remove(outputFile.Name())

	// stream of filem, output path, config, log)
	err = encrypt(input, outputFile.Name(), cfg, log)
	if err != nil {
		t.Errorf("Failed to encrypt")
	}

	var decBuf bytes.Buffer
	err = decrypt(&decBuf, outputFile.Name(), cfg.FileCTREncryptionKey, cfg.FileCTRHmacKey, log)
	if err != nil {
		t.Errorf("Failed to decrypt, err: %v", err)
	}
	if expectedValue != string(decBuf.Bytes()) {
		t.Errorf("invalid value, expected: %s, got: %s", expectedValue, string(decBuf.Bytes()))
	}

}

func TestBigEncryptDecrypt(t *testing.T) {
	log := zaptest.NewLogger(t)
	cfg := &config.Setting{
		FileCTRHmacKey:       getRandomEncryptionKey(),
		FileCTREncryptionKey: getRandomEncryptionKey(),
		EncryptKeyVersion:    "v1",
	}
	inputFile, err := ioutil.TempFile("", "encTestInTmpFile")
	if err != nil {
		t.Errorf("Failed to create input temp file for encryption test")
	}
	defer os.Remove(inputFile.Name())
	// some random nonesense
	expectedValue := getExpectedValue(16 * 1024)
	w := bufio.NewWriter(inputFile)
	_, err = w.WriteString(expectedValue)
	if err != nil {
		t.Errorf("Failed to write to input temp file for encryption test")
	}
	w.Flush()

	input, err := os.Open(inputFile.Name())
	if err != nil {
		t.Errorf("Failed to load input temp file for encryption test")
	}
	outputFile, err := ioutil.TempFile("", "encTestOutTmpFile")
	if err != nil {
		t.Errorf("Failed to create output temp file for encryption test")
	}
	defer os.Remove(outputFile.Name())

	// stream of filem, output path, config, log)
	err = encrypt(input, outputFile.Name(), cfg, log)
	if err != nil {
		t.Errorf("Failed to encrypt")
	}
	var decBuf bytes.Buffer
	err = decrypt(&decBuf, outputFile.Name(), cfg.FileCTREncryptionKey, cfg.FileCTRHmacKey, log)
	if err != nil {
		t.Errorf("Failed to decrypt")
	}
	if expectedValue != string(decBuf.Bytes()) {
		t.Errorf("invalid value, expected: %s, got: %s", expectedValue, string(decBuf.Bytes()))
	}

}

func getRandomEncryptionKey() string {
	c := 32
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}
	dst := make([]byte, hex.EncodedLen(len(b)))

	hex.Encode(dst, b)
	return string(dst)
}

func getExpectedValue(size int) string {
	var res string
	for i := 0; i < size; i++ {
		res += getRandomEncryptionKey()
	}
	return res
}
