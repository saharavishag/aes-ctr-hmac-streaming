package dump

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"dip-csp/pkg/config"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.uber.org/zap"
)

const bufferSize int = 16 * 1024 // buffer size of 16 MB - chunck size
const ivSize int = 16            // initial vector of counter in size of 16 bytes
const hmacSize = sha512.Size     // 64 bytes (512 bits)

// initEncryption(filePath, cfg, log, buffer stream channel), create a listening loop on channel, encrypt chunk by chunk

// This function encrypts from reader in AES CTR (counter) mode and saves it in filePath as encrypted file
// This function also creates hmac authentication tag the data and saves it within the encrypted file
// encrypted file structure:
// <IV/Nonce><chunk-0><tag-0><chunk-1><tag-1>...<chunk-n><tag-n>
// each auth tag authenticate all of the previous chunks included the current
func encrypt(reader io.Reader, filePath string, cfg *config.Setting, log *zap.Logger) error {
	defer timeTrack(time.Now(), "encrypt", log)
	log.Info("Starting file encryption")
	encryptKey, hmacKey, err := getEncryptionKeysByVersion(cfg.EncryptKeyVersion, cfg, log)
	if err != nil {
		return err
	}
	// decoding the keys
	decodedKey, err := hex.DecodeString(encryptKey)
	if err != nil {
		log.Error("Error decoding decodedKey", zap.Error(err))
		return err
	}
	decodedHmacKey, err := hex.DecodeString(hmacKey)
	if err != nil {
		log.Error("Error decoding decodedKey", zap.Error(err))
		return err
	}

	// get aes instance using decodedKey of 32 bytes (256 bits)
	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		log.Error("Error reading decodedKey", zap.Error(err))
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
	localHmac := hmac.New(sha512.New, decodedHmacKey)

	// create encrypted file
	file, err := os.Create(filePath)
	if err != nil {
		log.Error("Error creating the encrypted file", zap.Error(err))
		return err
	}
	defer func() {
		if errFile := file.Close(); errFile != nil {
			log.Error("Error closing ecrypted file", zap.Error(errFile))
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
	if err != nil || n != ivSize {
		log.Error("Error writing IV", zap.Error(err))
		return err
	}
	log.Info(fmt.Sprintf("Wrote IV successful, writing to disk. IV size: %v", n))

	chunkCnt := 0
	// create buffer to read to
	byteBuffer := make([]byte, bufferSize)
	for {
		// n is the number of bytes read
		// read returns an io.EOF error when the stream ends
		n, err := reader.Read(byteBuffer)

		if err != nil && err != io.EOF {
			log.Error("Error reading bytes from memory", zap.Error(err))
			return err
		}
		// bytes has been read
		if n != 0 {
			// log.Debug(fmt.Sprintf("Read %d bytes from memory...", n))
			chunkCnt++
			encryptedBuffer := make([]byte, n)
			// encrypt byteBuffer into encryptedBuffer
			ctr.XORKeyStream(encryptedBuffer, byteBuffer[:n])
			// write encrypted data
			n, err = writer.Write(encryptedBuffer)
			if err != nil {
				log.Error("Error writing bytes to encrypted file", zap.Error(err))
				return err
			}
			// log.Debug(fmt.Sprintf("Wrote %d bytes to file and hmac...", n))
			// streaming authentication
			authTag := localHmac.Sum(nil)
			// log.Debug(fmt.Sprintf("size of hash: %d", len(authTag)))
			n, err = encryptedFileWriter.Write(authTag)

			if err != nil {
				log.Error("Error writing auth tag to encrypted file", zap.Error(err))
				return err
			}
			// log.Debug(fmt.Sprintf("Wrote %d bytes of auth tag to file...", n))
		}
		if err == io.EOF {
			break
		}
	}

	encryptedFileWriter.Flush()
	log.Info(fmt.Sprintf("Encryption successful, written %v chunks to disk.", chunkCnt), zap.String("filePath", filePath))
	return err
}

// This function decrypts encrypted file of filePath and writes it using writer provided
// This function also verifies authenticity
func decrypt(writer io.Writer, filePath, ctrEncryptionKey, ctrHmacKey string, log *zap.Logger) error {
	defer timeTrack(time.Now(), "decrypt", log)
	log.Info("Starting file decryption", zap.String("filePath", filePath))

	// decoding the keys
	key, err := hex.DecodeString(ctrEncryptionKey)
	if err != nil {
		log.Error("Error decoding key", zap.Error(err))
		return err
	}
	hmacKey, err := hex.DecodeString(ctrHmacKey)
	if err != nil {
		log.Error("Error decoding key", zap.Error(err))
		return err
	}

	// open ecrypted file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error("Error opening ecrypted file", zap.Error(err))
	}
	defer func() {
		if errFile := file.Close(); errFile != nil {
			log.Error("Error closing ecrypted file", zap.Error(errFile))
		}
		log.Info("Closed encrypted file successfully")
	}()

	// read IV from the beginning of the file
	iv := make([]byte, ivSize)
	n, err := io.ReadFull(file, iv)
	if err != nil {
		log.Error("Error reading IV from encrypted file.", zap.Error(err))
		return err
	}
	log.Info(fmt.Sprintf("Reading IV from file successful. IV size: %v", n))

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error("Error reading key", zap.Error(err))
		return err
	}

	// get aes ctr instance
	ctr := cipher.NewCTR(block, iv)

	// get new hmac instance to calculate the local authentication
	localHmac := hmac.New(sha512.New, hmacKey)
	localHmac.Write(iv)

	// creates buffer reader out of reader
	bufferReader := bufio.NewReaderSize(file, bufferSize)

	chunkCnt := 0
	// buffer of size bufferSize + hmacSize so we'll read both from encrypted file each iteration
	buffer := make([]byte, bufferSize+hmacSize)
	for {
		n, err := io.ReadFull(bufferReader, buffer)
		if err == io.EOF {
			break
		}
		// log.Debug(fmt.Sprintf("Read encrypted data in size of: %d", n)) // wasteful

		encryptedDataSize := n - hmacSize

		// write encrypted data chunk into hmac
		localHmac.Write(buffer[:encryptedDataSize])
		authTag := localHmac.Sum(nil)
		// log.Debug(fmt.Sprintf("size of hash: %d", len(authTag))) // wasteful

		// verify the information is authenticated
		// tag - i
		if !hmac.Equal(buffer[encryptedDataSize:n], authTag) {
			errMessage := "Error authenticating the file - auth tags are not equal"
			log.Error(errMessage)
			return errors.New(errMessage)
		}

		outBuffer := make([]byte, int64(encryptedDataSize))
		// decrypt buffer data chunk into outBuffer
		ctr.XORKeyStream(outBuffer, buffer[:encryptedDataSize])
		// send decrypted data upstream
		writer.Write(outBuffer)
		chunkCnt++
		// log.Debug(fmt.Sprintf("Appended decrypted data of %d bytes to memory...", len(buffer[:encryptedDataSize]))) // wasteful
	}
	log.Info(fmt.Sprintf("Decryption successful. Decrypted %v chunks", chunkCnt))
	return nil
}

func getEncryptionKeysByVersion(version string, cfg *config.Setting, log *zap.Logger) (string, string, error) {
	log.Info("getting encryption key by version", zap.String("required version:", version))
	if version == "v1" {
		return cfg.FileCTREncryptionKey, cfg.FileCTRHmacKey, nil
	}
	if version == "v2" {
		return cfg.FileCTREncryptionKeyV2, cfg.FileCTRHmacKeyV2, nil
	}
	return "", "", errors.New("unrecognized encryption key version:" + version)
}
