package encryption

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestEncryptDecrypt(t *testing.T) {
	log := zaptest.NewLogger(t)
	fileEncryptionKeyV2 := getRandomEncryptionKey()
	inputFile, err := ioutil.TempFile("", "encTestInTmpFile")
	if err != nil {
		t.Errorf("Failed to create input temp file for encryption test")
	}
	defer os.Remove(inputFile.Name())

	// some random nonesense
	expectedValue := getExpectedValue()
	w := bufio.NewWriter(inputFile)
	_, err = w.WriteString(expectedValue)
	if err != nil {
		t.Errorf("Failed to write to input temp file for encryption test")
	}
	w.Flush()

	input, err := ioutil.ReadFile(inputFile.Name())
	if err != nil {
		t.Errorf("Failed to load input temp file for encryption test")
	}
	outputFile, err := ioutil.TempFile("", "encTestOutTmpFile")
	if err != nil {
		t.Errorf("Failed to create output temp file for encryption test")
	}
	defer os.Remove(outputFile.Name())

	// stream of filem, output path, config, log)
	err = encrypt(input, outputFile.Name(), fileEncryptionKeyV2, log)
	if err != nil {
		t.Errorf("Failed to encrypt")
	}
	res, err := decrypt(outputFile.Name(), fileEncryptionKeyV2, log)
	if err != nil {
		t.Errorf("Failed to decrypt")
	}
	if expectedValue != string(res) {
		t.Errorf("invalid value, expected: %s, got: %s", expectedValue, string(res))
	}

}

func TestBigEncryptDecrypt(t *testing.T) {
	log := zaptest.NewLogger(t)
	fileEncryptionKeyV2 := getRandomEncryptionKey()

	inputFile, err := ioutil.TempFile("", "encTestInTmpFile")
	if err != nil {
		t.Errorf("Failed to create input temp file for encryption test")
	}
	defer os.Remove(inputFile.Name())
	// some random nonesense
	expectedValue := getBigExpectedValue()
	w := bufio.NewWriter(inputFile)
	_, err = w.WriteString(expectedValue)
	if err != nil {
		t.Errorf("Failed to write to input temp file for encryption test")
	}
	w.Flush()

	input, err := ioutil.ReadFile(inputFile.Name())
	if err != nil {
		t.Errorf("Failed to load input temp file for encryption test")
	}
	outputFile, err := ioutil.TempFile("", "encTestOutTmpFile")
	if err != nil {
		t.Errorf("Failed to create output temp file for encryption test")
	}
	defer os.Remove(outputFile.Name())

	// stream of filem, output path, config, log)
	err = encrypt(input, outputFile.Name(), fileEncryptionKeyV2, log)
	if err != nil {
		t.Errorf("Failed to encrypt")
	}
	res, err := decrypt(outputFile.Name(), fileEncryptionKeyV2, log)
	if err != nil {
		t.Errorf("Failed to decrypt")
	}
	if expectedValue != string(res) {
		t.Errorf("invalid value, expected: %s, got: %s", expectedValue, string(res))
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

func getExpectedValue() string {
	var res string
	for i := 0; i < 10; i++ {
		res += getRandomEncryptionKey()
	}
	return res
}

func getBigExpectedValue() string {
	var res string
	for i := 0; i < (16 * 1024); i++ {
		res += getRandomEncryptionKey()
	}
	return res
}
