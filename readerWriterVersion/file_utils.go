package dump

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func timeTrack(start time.Time, name string, log *zap.Logger) {
	elapsed := time.Since(start)
	log.Info(fmt.Sprintf("TIMER: %s took %s", name, elapsed))
}

func getTimeAndSendGauge(start time.Time, name string, counter *prometheus.GaugeVec, log *zap.Logger) {
	elapsed := time.Since(start)
	log.Info(fmt.Sprintf("TIMER: %s took %s", name, elapsed))
	counter.WithLabelValues().Set(elapsed.Seconds())
}

func getSHA256CheckSum(filePath string, log *zap.Logger) (string, error) {
	defer timeTrack(time.Now(), "getSHA256CheckSum", log)
	f, err := os.Open(filePath)
	if err != nil {
		log.Error(fmt.Sprintf("Can't open file %s", filePath), zap.Error(err))
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Error(fmt.Sprintf("Can't calculate sha256 checksum file %s", filePath), zap.Error(err))
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateSHA256CheckSum(filePath string, log *zap.Logger) (bool, error) {
	split := strings.Split(filePath, "_")
	if len(split) != 8 {
		return false, errors.New("Can't validate sha256, file is not in correct format. file path: " + filePath)
	}
	expected := split[6] // csp_store_dump_{version}_{enc key version}_{date}_{expected sha key}_.gob
	chksum, err := getSHA256CheckSum(filePath, log)
	if err != nil {
		return false, err
	}
	return chksum == expected, nil
}

//file path is a path to directory and should end with a '/' e.g. "/go/dump/"
//returns csp_store_dump_{apiversion}_{keyversion}_{date}_{expected sha key}_.gob
func getFormattedDumpFileName(fileName string, filePath string, log *zap.Logger, internalApiVersion, encryptionKeyVersion string) (string, error) {
	date := strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", "-") //file name shouldn't contain colons
	chksum, err := getSHA256CheckSum(fileName, log)
	if err != nil {
		return "", err
	}
	newFileName := fmt.Sprintf("csp_store_dump_%s_%s_%s_%s_.gob", internalApiVersion, encryptionKeyVersion, date, chksum)
	return filePath + newFileName, nil
}

/*
this function gets a dump file path that is structured as
/csp/dump/csp_store_dump_{apiversion}_{keyversion}_{date}_{expected sha key}_.gob
and returns an ordered string tuple {{apiversion}, {keyversion}}
e.g. /csp/dump/csp_store_dump_v3_v1_{date}_{expected sha key}_.gob -> {{v3, v1}}
*/
func getVersionsFromFilePath(filePath string) (string, string) {
	split := strings.Split(filePath, "_")
	if len(split) != 8 {
		return "", ""
	}
	return split[3], split[4]
}
