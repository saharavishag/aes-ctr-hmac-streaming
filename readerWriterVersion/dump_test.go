package dump

import (
	"dip-csp/pkg/config"
	"dip-csp/pkg/metrics"
	"dip-csp/pkg/servicediscovery"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type consulHandlerMock struct {
}

func init() {
	metrics.InitMetrics(&config.Setting{})
}

func (ch *consulHandlerMock) GetHealthyCspBe() ([]servicediscovery.CspInstance, error) {
	return []servicediscovery.CspInstance{{Ip: "1", Name: "one"}, {Ip: "2", Name: "two"}, {Ip: "3", Name: "three"}}, nil
}

var consulMock servicediscovery.ServiceDiscovery
var cfg *config.Setting
var log *zap.Logger
var oldGetSnapshotFunc func(csp *servicediscovery.CspInstance, log *zap.Logger, cfg *config.Setting) error
var oldIsCspHealthyFunc func(csp *servicediscovery.CspInstance, cfg *config.Setting, log *zap.Logger) error

func setUp(t *testing.T) {
	consulMock = &consulHandlerMock{}
	oldGetSnapshotFunc = getSnapshotFromCspFunc
	cfg = &config.Setting{}
	log = zaptest.NewLogger(t, zaptest.Level(zap.FatalLevel))
}

func tearDown() {
	getSnapshotFromCspFunc = oldGetSnapshotFunc
}

func Test_getUnmarkedCspIp(t *testing.T) {
	all := []servicediscovery.CspInstance{{Ip: "1", Name: ""}, {Ip: "2", Name: ""}, {Ip: "3", Name: ""}, {Ip: "4", Name: ""}}
	marked := map[string]bool{"1": true, "2": true}
	result, err := getUnmarkedCsp(all, marked)
	assert.Equal(t, err, nil)
	assert.Equal(t, result.Ip, "3")
}

func Test_getUnmarkedCspIpError(t *testing.T) {
	all := []servicediscovery.CspInstance{{Ip: "1", Name: ""}, {Ip: "2", Name: ""}}
	marked := map[string]bool{"1": true, "2": true}
	_, err := getUnmarkedCsp(all, marked)
	assert.Equal(t, err.Error(), "No unmarked CSPs")
}

func TestGetSnapshotFromLatestCspRetry(t *testing.T) {
	setUp(t)
	defer tearDown()
	getSnapshotFromCspFunc = func(csp *servicediscovery.CspInstance, log *zap.Logger, cfg *config.Setting) error {
		if csp.Ip == "3" { //succeed on third retry only
			return nil
		}
		return errors.New("dummy error")
	}
	err := GetSnapshotFromLatestCspRetry(consulMock, log, cfg, 0)
	assert.Equal(t, err, nil)
}

func TestGetSnapshotFromLatestCspRetryError(t *testing.T) {
	setUp(t)
	defer tearDown()
	getSnapshotFromCspFunc = func(csp *servicediscovery.CspInstance, log *zap.Logger, cfg *config.Setting) error {
		return errors.New("dummy error") //always fail
	}
	err := GetSnapshotFromLatestCspRetry(consulMock, log, cfg, 0)
	assert.Equal(t, err.Error(), "Snapshot download failed, max retries")
}
