package dump

import (
	"dip-csp/pkg/api/http_utils"
	"dip-csp/pkg/config"
	"dip-csp/pkg/httpclient"
	"dip-csp/pkg/metrics"
	"dip-csp/pkg/queueconsumer"
	"dip-csp/pkg/servicediscovery"
	"dip-csp/pkg/store"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
)

const dumpDir = "/go/dump/"
const maxRetries = 3
const retrySleepTime = time.Second * 30
const timeOutSnapshot = time.Second * 90

var dumpFileName string
var getSnapshotFromCspFunc = getSnapshotFromCsp //for testing
var filePath = ""
var migrationPrevApiVersion = "v3"

func InitConsumption(consumer queueconsumer.QueueConsumer, store *store.DataStore, log *zap.Logger, cfg *config.Setting) {
	log.Info("Try to download snapshot")
	err := downloadSnapshot(log, cfg)
	if err != nil {
		log.Error("file download failed", zap.Error(err))
	}
	log.Info("initial kafka connect")
	for !consumer.Connect() {
		time.Sleep(cfg.ConsumerSyncCheckSleep)
	}
	log.Info("starting deserializing from file")
	// decrypt streaming and decode
	err = deserializeFromFile(filePath, consumer, store, cfg, log)
	if err != nil {
		// alert is based on this line.
		log.Error("deserializeFromFile failed", zap.Error(err))
		consumer.ResetPartitionOffsets() //if deserialize fails we want to read from offset 0 of kafka topic
	}
	// remove old dump after it's in mem
	go tryRemoveFile(filePath, log)

	// assign partitions for consumption. could be zero offset
	log.Info("call Assign() on kafka consumer")
	if err := consumer.Assign(); err != nil {
		log.Panic("Error on Assign for init.", zap.Error(err))
	}
}

// SerializeToFile takes imporant data from store and kafka consumer and writes to file
func SerializeToFile(store *store.DataStore, consumer queueconsumer.QueueConsumer, cfg *config.Setting, log *zap.Logger) error {
	defer timeTrack(time.Now(), "SerializeToFile", log)
	tempFile := dumpDir + "tmp.gob"
	// var w bytes.Buffer
	bs := newBS(log)
	var err error
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err = encrypt(bs, tempFile, cfg, log) // runs async as it reads whatever encoder writes
		bs.discardReader()                    // in case of early exit in reader this avoids deadlock in writer
		wg.Done()
	}()
	enc := gob.NewEncoder(bs)
	// serialize offsets
	store.EncodePartitionOffsets(enc, consumer)
	// serialize store
	store.EncodeStore(enc)
	bs.flush()
	// wait for encryption to finish
	wg.Wait()

	if err != nil {
		log.Error("Failed to encrypt file", zap.Error(err))
		errRm := os.Remove(tempFile)
		if errRm != nil {
			log.Error("Failed to remove file", zap.Error(errRm))
		}
		return err
	}

	//rename file according to format, adding SHA256
	if dumpFileName, err = getFormattedDumpFileName(tempFile, dumpDir, log, cfg.InternalApiVersion, cfg.EncryptKeyVersion); err != nil {
		dumpFileName = ""
		log.Error("Failed to create formatted filename", zap.Error(err))
		return err
	}
	log.Info(fmt.Sprintf("Renaming tempFile: %v to dumpFileName: %v", tempFile, dumpFileName))
	if err = os.Rename(tempFile, dumpFileName); err != nil {
		dumpFileName = ""
		log.Error("Failed to rename file", zap.Error(err))
		return err
	}

	return nil
}

// DeserializeFromFile takes data from file created by SerializeToFile and calls consumer and store to decode it
func deserializeFromFile(filePath string, consumer queueconsumer.QueueConsumer, store *store.DataStore, cfg *config.Setting, log *zap.Logger) error {
	defer timeTrack(time.Now(), "deserializeFromFile", log)
	if filePath == "" {
		return errors.New("deserializeFromFile - filePath shouldn't be empty")
	}
	apiVersion, keyVersion := getVersionsFromFilePath(filePath)
	log.Info("deseralizing file using file and key versions", zap.String("api_version", apiVersion), zap.String("key_version", keyVersion))
	if apiVersion == "" || keyVersion == "" || (apiVersion != cfg.InternalApiVersion && apiVersion != migrationPrevApiVersion) {
		return fmt.Errorf("Invalid file or key version detected")
	}
	encryptKey, hmacKey, err := getEncryptionKeysByVersion(keyVersion, cfg, log)
	if err != nil {
		return err
	}
	// verify authenticity of encrypted file:
	if err = verifyAuth(filePath, encryptKey, hmacKey, log); err != nil {
		return err
	}

	// encrypt write to same file
	bs := newBS(log)
	var decrErr error
	go func() {
		decrErr = decrypt(bs, filePath, encryptKey, hmacKey, log) // writes using bs.Write
		bs.flush()                                                // finalizes the write
	}()

	// TODO rip migration. create new key migration FLYB-949

	defer bs.discardReader() // avoid stuck decryption in case of failure in stream decode
	dec := gob.NewDecoder(bs)

	// call consumer to decode partition offset info memory
	if err = consumer.DecodePartitionOffsets(dec); err != nil {
		return err
	}

	// call store to decode namespace data
	if err = store.DecodeStore(dec); err != nil {
		return err
	}

	// dummy just to verify EOF
	dummy := -1
	err = dec.Decode(&dummy)
	if err == nil {
		// weird if this happens.
		log.Error("Expected error to be EOF. Got nil", zap.Int("dummy", dummy))
	} else if err.Error() != "EOF" {
		// more data unread implies an issue
		log.Warn("Unexpected error", zap.Error(err))
	}

	if decrErr != nil {
		log.Error("Failed to decrypt file", zap.Error(err))
		return err
	}
	return nil
}

func verifyAuth(filePath, fileCTREncryptionKey, fileCTRHmacKey string, log *zap.Logger) error {
	return decrypt(ioutil.Discard, filePath, fileCTREncryptionKey, fileCTRHmacKey, log) // execute once in full and check err (throw output)
}

func downloadSnapshot(log *zap.Logger, cfg *config.Setting) error {
	consulHandler, err := servicediscovery.Init(cfg, log)
	if err != nil {
		log.Error("Consul Init failed", zap.Error(err))
		return err
	}
	return GetSnapshotFromLatestCspRetry(consulHandler, log, cfg, retrySleepTime)
}

func GetSnapshotFromLatestCspRetry(consulHandler servicediscovery.ServiceDiscovery, log *zap.Logger, cfg *config.Setting, sleepTime time.Duration) error {
	markedSkipCsps := make(map[string]bool)
	for i := 0; i < maxRetries; i++ {
		healthyCsps, err := consulHandler.GetHealthyCspBe()
		if err != nil {
			log.Error("Error in getting active csps", zap.Error(err))
			return err
		}
		if len(healthyCsps) == 0 {
			err := errors.New("no active csps exist, list is empty")
			log.Error("healthy Csps list is empty", zap.Error(err))
			return err
		}
		log.Info("csp list from consul", zap.Any("cspList", healthyCsps))
		csp, err := getUnmarkedCsp(healthyCsps, markedSkipCsps)
		if err != nil {
			log.Error("Get unmarked CSP ip failed", zap.Error(err))
			return err
		}

		start := time.Now()
		err = getSnapshotFromCspFunc(csp, log, cfg) //using the Latest CSP
		if err == nil {                             //snapshot downloaded successfully
			getTimeAndSendGauge(start, "DumpFileDownloadTime", metrics.DumpFileDownloadTime, log)
			return err
		}
		log.Error("Snapshot download failed", zap.Error(err), zap.Int("Retries", i))
		markedSkipCsps[csp.Ip] = true //mark csp as should be skipped.
		if !isTimeout(err) {
			time.Sleep(sleepTime)
		}
	}
	return errors.New("Snapshot download failed, max retries")
}

func isTimeout(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout")
}

func getUnmarkedCsp(all []servicediscovery.CspInstance, marked map[string]bool) (*servicediscovery.CspInstance, error) {
	for _, csp := range all {
		if _, ok := marked[csp.Ip]; !ok { //return first unmarked csp
			return &csp, nil
		}
	}
	return nil, errors.New("No unmarked CSPs")
}

func createSnapshotRequest(csp *servicediscovery.CspInstance, log *zap.Logger, token, apiVersion string) (*retryablehttp.Request, error) {
	snapshotUrl := "/api/" + apiVersion + "/getsnapshot"
	cspAddress := fmt.Sprintf("https://%v%v%v", csp.Ip, httpsAddr, snapshotUrl)
	log.Info(fmt.Sprintf("getting snapshot from: %v", cspAddress))
	auth, err := httpclient.CreateHttpRequestWithAuth(token, cspAddress, log)
	return auth, err
}

func getSnapshotFromCsp(csp *servicediscovery.CspInstance, log *zap.Logger, cfg *config.Setting) error {
	const maxRetries = 3
	req, err := createSnapshotRequest(csp, log, cfg.InternalClientCspBeTokenString, cfg.InternalApiVersion)
	if err != nil {
		log.Error(fmt.Sprintf("Error getting snapshot request %v, target Csp: %v", err, csp))
		return err
	}
	client := httpclient.CreateHttpClient(cfg.CspCertHost, timeOutSnapshot, maxRetries, log)
	response, err := client.Do(req)
	if err != nil {
		log.Error(fmt.Sprint("Error while downloading", zap.Error(err)))
		return err
	}
	log.Info(fmt.Sprintf("got response status: %s", response.Status))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		ioutil.ReadAll(response.Body)
		log.Error("response status not OK", zap.Int("status_code", response.StatusCode))
		return errors.New(fmt.Sprintf("got error response status %v", response.Status))
	}
	fileName, err := http_utils.GetFileNameFromHeader(response.Header.Get("Content-Disposition"), log)
	if err != nil {
		return err
	}

	filePath = dumpDir + fileName
	output, err := os.Create(filePath)
	if err != nil {
		log.Error(fmt.Sprint("Error while creating", fileName, "-", zap.Error(err)))
		return err
	}

	n, err := io.Copy(output, response.Body)
	if err != nil {
		log.Error(fmt.Sprint("Error copying payload to file", zap.Error(err)))
		return err
	}

	output.Close()
	validCheckSum, err := validateSHA256CheckSum(filePath, log)
	if err != nil {
		log.Error(fmt.Sprint("Error validate checkSum", zap.Error(err)))
		return err
	}
	if !validCheckSum {
		log.Error(fmt.Sprint("checkSum validation failed", zap.Error(err)))
		tryRemoveFile(filePath, log)
		return errors.New("checkSum validation failed")
	}
	log.Info(fmt.Sprint(n, " bytes downloaded."))
	return nil
}

func tryRemoveFile(path string, log *zap.Logger) {
	if err := os.Remove(path); err != nil {
		log.Error(fmt.Sprintf("Failed to remove file %s", path), zap.Error(err))
	}
}
