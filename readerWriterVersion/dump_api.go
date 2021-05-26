package dump

import (
	"dip-csp/pkg/api/auth"
	"dip-csp/pkg/api/http_utils"
	"dip-csp/pkg/config"
	"dip-csp/pkg/logging"
	"dip-csp/pkg/metrics"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const httpsAddr = ":10443"

func StartInternalApi() error {
	cfg := config.GetConfig()
	log := logging.GetLogger()
	if dumpFileName == "" {
		return errors.New("Can't start snapshot api, dump file name is empty")
	}
	router := mux.NewRouter().StrictSlash(true)
	router.Use(auth.SecureHeadersMiddleware)

	internalApi := router.PathPrefix("/api").Subrouter()
	internalApi.Use(metrics.Middleware(nil, "internal"))
	internalApi.Use(auth.Middleware(cfg.InternalUseTokenMap, "internal", nil))
	applyInternalRoutes(internalApi, log, cfg)

	log.Info("Starting internal API", zap.String("serving dumpFileName", dumpFileName))
	return http_utils.StartHTTPServer(router, httpsAddr, cfg, log)
}

func applyInternalRoutes(router *mux.Router, log *zap.Logger, cfg *config.Setting) {
	snapshotHandler := createSnapshotHandler(dumpFileName, filepath.Base(dumpFileName), log)
	router.HandleFunc("/"+cfg.InternalApiVersion+"/getsnapshot", snapshotHandler).Methods(http.MethodGet)
	snapshotMigrationHandler := createSnapshotHandler(dumpFileName, getMigrationServingName(filepath.Base(dumpFileName), cfg.InternalApiVersion, cfg.EncryptKeyVersion), log)
	router.HandleFunc("/v3/getsnapshot", snapshotMigrationHandler).Methods(http.MethodGet)
}

func getMigrationServingName(dumpFileName, apiVersion, keyVersion string) string {
	sep := apiVersion + "_" + keyVersion
	split := strings.Split(dumpFileName, sep) // csp_store_dump_$APIVERSION_$KEYVERSION_$DATE_$HASH_.gob will be split to [csp_store_dump_, _$DATE_$HASH_.gob]
	fmt.Println(split)
	if len(split) != 2 || split[0] != "csp_store_dump_" {
		return dumpFileName
	}
	return split[0] + migrationPrevApiVersion + split[1] //csp_store_dump_v3_$DATE_$HASH_.gob
}

func createSnapshotHandler(dumpPath, servingName string, log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(dumpPath); os.IsNotExist(err) {
			log.Error(fmt.Sprintf("Can't find served file %s", dumpPath))
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, servingName))
		http.ServeFile(w, r, dumpPath)
	}
}
