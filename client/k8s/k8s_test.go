package k8s

import (
	"os"

	"fmt"
	"testing"

	"github.com/giantswarm/microkit/logger"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/giantswarm/cert-operator/flag"
)

func TestGetRawClientConfig(t *testing.T) {
	var err error
	var newLogger logger.Logger

	{
		loggerConfig := logger.DefaultConfig()
		loggerConfig.IOWriter = os.Stdout
		newLogger, err = logger.New(loggerConfig)
		if err != nil {
			panic(err)
		}
	}

	certFile := "/var/run/kubernetes/client-admin.crt"
	keyFile := "/var/run/kubernetes/client-admin.key"
	caFile := "/var/run/kubernetes/server-ca.crt"

	tests := []struct {
		name            string
		inCluster       bool
		expectedError   bool
		expectedAddress string
	}{
		{
			name:            "Specify out-cluster config. It should return it. Use cert auth files.",
			inCluster:       false,
			expectedError:   false,
			expectedAddress: "http://out-cluster-host",
		},
		{
			name:            "Specify out-cluster config. It should error due to missing k8s address.",
			inCluster:       false,
			expectedError:   true,
			expectedAddress: "",
		},
		{
			name:            "Specify out-cluster config. It should error due to invalid k8s address.",
			inCluster:       false,
			expectedError:   false,
			expectedAddress: "invalid-host",
		},
		{
			name:            "Specify in-cluster config. Currently errors due to missing k8s env vars.",
			inCluster:       true,
			expectedError:   true, // TODO Get in-cluster config working in tests.
			expectedAddress: "invalid-host",
		},
	}
	for _, tc := range tests {
		f := flag.New()
		v := viper.New()

		v.Set(f.Kubernetes.InCluster, tc.inCluster)
		v.Set(f.Kubernetes.Address, tc.expectedAddress)
		v.Set(f.Kubernetes.TLS.CertFile, certFile)
		v.Set(f.Kubernetes.TLS.KeyFile, keyFile)
		v.Set(f.Kubernetes.TLS.CAFile, caFile)

		config := Config{
			Logger: newLogger,

			Flag:  f,
			Viper: v,
		}

		rawClientConfig, err := getRawClientConfig(config)
		if tc.expectedError {
			assert.Error(t, err, fmt.Sprintf("[%s] An error was expected", tc.name))
			continue
		}
		assert.Nil(t, err, fmt.Sprintf("[%s] An error was unexpected", tc.name))
		assert.Equal(t, tc.expectedAddress, rawClientConfig.Host, fmt.Sprintf("[%s] Hosts should be equal", tc.name))
		assert.Equal(t, certFile, rawClientConfig.TLSClientConfig.CertFile, fmt.Sprintf("[%s] CertFiles should be equal", tc.name))
		assert.Equal(t, keyFile, rawClientConfig.TLSClientConfig.KeyFile, fmt.Sprintf("[%s] KeyFiles should be equal", tc.name))
		assert.Equal(t, caFile, rawClientConfig.TLSClientConfig.CAFile, fmt.Sprintf("[%s] CAFiles should be equal", tc.name))
	}
}
