package storj

import (
	"os"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/testsuites"
	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { check.TestingT(t) }

var storjDriverConstructor func() (*Driver, error)

var skipStorj func() string

func init() {
	accessGrant := os.Getenv("STORJ_ACCESS_GRANT")
	bucket := os.Getenv("STORJ_BUCKET")

	storjDriverConstructor = func() (*Driver, error) {
		parameters := DriverParameters{
			accessGrant,
			bucket,
		}

		return New(parameters)
	}

	// Skip S3 storage driver tests if environment variable parameters are not provided
	skipStorj = func() string {
		if accessGrant == "" || bucket == "" {
			return "Must set STORJ_ACCESS_GRANT and STORJ_BUCKET to run Storj tests"
		}
		return ""
	}

	testsuites.RegisterSuite(func() (storagedriver.StorageDriver, error) {
		return storjDriverConstructor()
	}, skipStorj)
}
