package encryption

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	// "time"
	"go.uber.org/zap"
)

const bufferSize int = 8 * 1024 // buffer size of 16 MB - chunck size
const ivSize int = 16            // initial vertor of counter in size of 16 bytes
const hmacSize = sha512.Size     // 64 bytes (512 bits)

// This function encrypts inMemFile in AES CTR (counter) mode and saves it in filePath as encrypted file
// This function also creates hmac authentication tag the data and saves it within the encrypted file
// encrypted file structure:
// <IV><chunk-0><tag-0><chunk-1><tag-1>...<chunk-n><tag-n>
// each auth tag authenticate all of the previous chunks included the current
func encrypt(inMemFile []byte, filePath string, fileEncryptionKey string, log *zap.Logger) error {
	log.Info("Starting file encryption")

	// decoding the key
	key, err := hex.DecodeString(fileEncryptionKey)
	if err != nil {
		log.Error("Error decoding key", zap.Error(err))
		return err
	}

	// get aes instance using key of 32 bytes (256 bits)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error("Error reading key", zap.Error(err))
		return err
	}

	// randomize initial vector (aka nonce/iv) in size of 16 bytes (128 bits)
	iv := make([]byte, ivSize)
	n, err := rand.Read(iv)
	if err != nil {
		log.Error("Error randomize IV", zap.Error(err))
		return err
	}
	log.Info(fmt.Sprintf("Randimized IV if size: %d successfully", n))

	// get aes ctr instance
	ctr := cipher.NewCTR(block, iv)

	// get hmac instance for authentication
	localHmac := hmac.New(sha512.New, key) // TODO: switch to new different key

	// create encrypted file
	file, err := os.Create(filePath)
	if err != nil {
		log.Error("Error creating the encrypted file", zap.Error(err))
		return err
	}
	defer func() {
		if err = file.Close(); err != nil {
			log.Error("Error closing ecrypted file", zap.Error(err))
		}
		log.Info("Closed file successfully")
	}()

	// create writer for the encrypted file
	encryptedFileWriter := bufio.NewWriter(file)

	// create unified writer for both encrypted data and authentication tag
	// when we write to it - both encryptedFileWriter.write and hmac.write will be called
	writer := io.MultiWriter(encryptedFileWriter, localHmac)

	// writing the IV at the beginning of the file and init hmac with it
	n, err = writer.Write(iv)
	if err != nil {
		log.Error("Error writing IV", zap.Error(err))
		return err
	}
	log.Info(fmt.Sprintf("Wrote IV successful, writing to disk. IV size: %v", n))

	// create inMemFile reader
	byteReader := bytes.NewReader(inMemFile)

	// create buffer to read to
	byteBuffer := make([]byte, bufferSize)
	for {
		// n is the number of bytes read
		// read returns an io.EOF error when the stream ends
		n, err := byteReader.Read(byteBuffer)

		if err != nil && err != io.EOF {
			log.Error("Error reading bytes from memory", zap.Error(err))
			return err
		}
		// bytes has been read
		if n != 0 {
			log.Debug(fmt.Sprintf("Read %d bytes from memory...", n))
			encryptedBuffer := make([]byte, n)
			// encrypt byteBuffer into encryptedBuffer
			ctr.XORKeyStream(encryptedBuffer, byteBuffer[:n])
			// write encrypted data
			n, err := writer.Write(encryptedBuffer)
			if err != nil {
				log.Error("Error writing bytes to encrypted file", zap.Error(err))
				return err
			}
			log.Debug(fmt.Sprintf("Wrote %d bytes to file and hmac...", n))
			// streaming authentication
			authTag := localHmac.Sum(nil)
			log.Debug(fmt.Sprintf("size of hash: %d", len(authTag)))
			n, err = writer.Write(authTag)
			if err != nil {
				log.Error("Error writing auth tag to encrypted file", zap.Error(err))
				return err
			}
			log.Debug(fmt.Sprintf("Wrote %d bytes of auth tag to file...", n))
		}
		if err == io.EOF {
			break
		}
	}
	encryptedFileWriter.Flush()
	log.Info(fmt.Sprintf("Encryption successful, writing to disk. inMemFile bytes: %v", len(inMemFile)), zap.String("filePath", filePath))
	return err
}

// This function decrypts encrypted file of filePath and loads it to the memory
// This function also verify authentication
// encrypted file structure:
// <IV><chunk-0><tag-0><chunk-1><tag-1>...<chunk-n><tag-n>
// each auth tag authenticate all of the previous chunks included the current
func decrypt(filePath string, fileEncryptionKey string, log *zap.Logger) ([]byte, error) {
	log.Info(fmt.Sprintf("Starting file decryption. filePath: %s", filePath))

	// decoding the key
	key, err := hex.DecodeString(fileEncryptionKey)
	if err != nil {
		log.Error("Error decoding key", zap.Error(err))
		return nil, err
	}

	// open ecrypted file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error("Error openning ecrypted file", zap.Error(err))
	}
	defer func() {
		if err = file.Close(); err != nil {
			log.Error("Error closing ecrypted file", zap.Error(err))
		}
		log.Info("Closed file successfully")
	}()

	// read IV from the beginning of the file
	iv := make([]byte, ivSize)
	n, err := io.ReadFull(file, iv)
	if err != nil {
		log.Error("Error reading IV from encrypted file.", zap.Error(err))
		return nil, err
	}
	log.Info(fmt.Sprintf("Reading IV from file successful. IV size: %v", n))

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error("Error reading key", zap.Error(err))
		return nil, err
	}

	// get aes ctr instance
	ctr := cipher.NewCTR(block, iv)

	// get new hmac instance to calculate the local authentication
	localHmac := hmac.New(sha512.New, key)
	localHmac.Write(iv)

	// creates buffer reader out of reader
	bufferReader := bufio.NewReaderSize(file, bufferSize)
	var decryptedData []byte

	// buffer of size bufferSize + hmacSize so we'll read both from encrypted file each iteration
	buffer := make([]byte, bufferSize+hmacSize)
	for {
		n, err := io.ReadFull(bufferReader, buffer)
		if err == io.EOF {
			break
		}
		log.Debug(fmt.Sprintf("Read encrypted data in size of: %d", n))

		encryptedDataSize := n - hmacSize

		// write encrypted data chunk into hmac
		localHmac.Write(buffer[:encryptedDataSize])
		authTag := localHmac.Sum(nil)
		log.Debug(fmt.Sprintf("size of hash: %d", len(authTag)))

		// verify the information is authenticate
		if !hmac.Equal(buffer[encryptedDataSize:n], authTag) {
			errMessage := "Error authenticating the file - auth tags are not equal"
			log.Error(errMessage)
			return nil, errors.New(errMessage)
		}

		// write current auth tag into hmac for the next verification
		localHmac.Write(authTag)

		outBuffer := make([]byte, int64(encryptedDataSize))
		// decrypt buffer data chunk into outBuffer
		ctr.XORKeyStream(outBuffer, buffer[:encryptedDataSize])
		// load the decrypted data to memory
		decryptedData = append(decryptedData, outBuffer...)
		log.Debug(fmt.Sprintf("Appended decrypted data of %d bytes to memory...", len(buffer[:encryptedDataSize])))
	}
	log.Info(fmt.Sprintf("Decryption successful. Size of decrypted: %v bytes", len(decryptedData)))
	return decryptedData, nil
}
