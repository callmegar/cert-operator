package service

import (
	"context"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/giantswarm/certificatetpr"
	"github.com/giantswarm/microerror"
	"github.com/giantswarm/operatorkit/client/k8sclient"
	"github.com/giantswarm/operatorkit/framework"
	"github.com/giantswarm/operatorkit/framework/resource/metricsresource"
	"github.com/giantswarm/operatorkit/framework/resource/retryresource"
	"github.com/giantswarm/operatorkit/informer"
	"github.com/giantswarm/operatorkit/tpr"
	"github.com/giantswarm/vaultcrt"
	"github.com/giantswarm/vaultpki"
	"github.com/giantswarm/vaultrole"
	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"

	vaultutil "github.com/giantswarm/cert-operator/client/vault"
	"github.com/giantswarm/cert-operator/service/resource/vaultcrtv1"
	"github.com/giantswarm/cert-operator/service/resource/vaultpkiv1"
)

const (
	ResourceRetries uint64 = 3
)

func newCustomObjectFramework(config Config) (*framework.Framework, error) {
	if config.Flag == nil {
		return nil, microerror.Maskf(invalidConfigError, "config.Flag must not be empty")
	}
	if config.Viper == nil {
		return nil, microerror.Maskf(invalidConfigError, "config.Viper must not be empty")
	}

	var err error

	var k8sClient kubernetes.Interface
	{
		k8sConfig := k8sclient.DefaultConfig()

		k8sConfig.Logger = config.Logger

		k8sConfig.Address = config.Viper.GetString(config.Flag.Service.Kubernetes.Address)
		k8sConfig.InCluster = config.Viper.GetBool(config.Flag.Service.Kubernetes.InCluster)
		k8sConfig.TLS.CAFile = config.Viper.GetString(config.Flag.Service.Kubernetes.TLS.CAFile)
		k8sConfig.TLS.CrtFile = config.Viper.GetString(config.Flag.Service.Kubernetes.TLS.CrtFile)
		k8sConfig.TLS.KeyFile = config.Viper.GetString(config.Flag.Service.Kubernetes.TLS.KeyFile)

		k8sClient, err = k8sclient.New(k8sConfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var vaultClient *vaultapi.Client
	{
		vaultConfig := vaultutil.Config{
			Flag:  config.Flag,
			Viper: config.Viper,
		}

		vaultClient, err = vaultutil.NewClient(vaultConfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var vaultCrt vaultcrt.Interface
	{
		c := vaultcrt.DefaultConfig()

		c.Logger = config.Logger
		c.VaultClient = vaultClient

		vaultCrt, err = vaultcrt.New(c)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var vaultPKI vaultpki.Interface
	{
		c := vaultpki.DefaultConfig()

		c.Logger = config.Logger
		c.VaultClient = vaultClient

		c.CATTL = config.Viper.GetString(config.Flag.Service.Vault.Config.PKI.CA.TTL)
		c.CommonNameFormat = config.Viper.GetString(config.Flag.Service.Vault.Config.PKI.CommonName.Format)

		vaultPKI, err = vaultpki.New(c)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var vaultRole vaultrole.Interface
	{
		c := vaultrole.DefaultConfig()

		c.Logger = config.Logger
		c.VaultClient = vaultClient

		c.CommonNameFormat = config.Viper.GetString(config.Flag.Service.Vault.Config.PKI.CommonName.Format)

		vaultRole, err = vaultrole.New(c)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var vaultCrtResource framework.Resource
	{
		c := vaultcrtv1.DefaultConfig()

		c.CurrentTimeFactory = func() time.Time { return time.Now() }
		c.K8sClient = k8sClient
		c.Logger = config.Logger
		c.VaultCrt = vaultCrt
		c.VaultRole = vaultRole

		c.ExpirationThreshold = config.Viper.GetDuration(config.Flag.Service.Resource.VaultCrt.ExpirationThreshold)
		c.Namespace = config.Viper.GetString(config.Flag.Service.Resource.VaultCrt.Namespace)

		vaultCrtResource, err = vaultcrtv1.New(c)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var vaultPKIResource framework.Resource
	{
		c := vaultpkiv1.DefaultConfig()

		c.Logger = config.Logger
		c.VaultPKI = vaultPKI

		vaultPKIResource, err = vaultpkiv1.New(c)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	// We create the list of resources and wrap each resource around some common
	// resources like metrics and retry resources.
	//
	// NOTE that the retry resources wrap the underlying resources first. The
	// wrapped resources are then wrapped around the metrics resource. That way
	// the metrics also consider execution times and execution attempts including
	// retries.
	//
	// NOTE that the order of the namespace resource is important. We have to
	// start the namespace resource at first because all other resources are
	// created within this namespace.
	var resources []framework.Resource
	{
		resources = []framework.Resource{
			vaultPKIResource,
			vaultCrtResource,
		}

		retryWrapConfig := retryresource.DefaultWrapConfig()
		retryWrapConfig.BackOffFactory = func() backoff.BackOff { return backoff.WithMaxTries(backoff.NewExponentialBackOff(), ResourceRetries) }
		retryWrapConfig.Logger = config.Logger
		resources, err = retryresource.Wrap(resources, retryWrapConfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}

		metricsWrapConfig := metricsresource.DefaultWrapConfig()
		metricsWrapConfig.Name = config.Name
		resources, err = metricsresource.Wrap(resources, metricsWrapConfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	initCtxFunc := func(ctx context.Context, obj interface{}) (context.Context, error) {
		return ctx, nil
	}

	var newTPR *tpr.TPR
	{
		c := tpr.DefaultConfig()

		c.K8sClient = k8sClient
		c.Logger = config.Logger

		c.Description = certificatetpr.Description
		c.Name = certificatetpr.Name
		c.Version = certificatetpr.VersionV1

		newTPR, err = tpr.New(c)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var newWatcherFactory informer.WatcherFactory
	{
		zeroObjectFactory := &informer.ZeroObjectFactoryFuncs{
			NewObjectFunc:     func() runtime.Object { return &certificatetpr.CustomObject{} },
			NewObjectListFunc: func() runtime.Object { return &certificatetpr.List{} },
		}
		newWatcherFactory = informer.NewWatcherFactory(k8sClient.Discovery().RESTClient(), newTPR.WatchEndpoint(""), zeroObjectFactory)
	}

	var newInformer *informer.Informer
	{
		informerConfig := informer.DefaultConfig()

		informerConfig.WatcherFactory = newWatcherFactory

		informerConfig.RateWait = 1 * time.Second
		informerConfig.ResyncPeriod = time.Minute * 5

		newInformer, err = informer.New(informerConfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	var customObjectFramework *framework.Framework
	{
		frameworkConfig := framework.DefaultConfig()

		frameworkConfig.Informer = newInformer
		frameworkConfig.InitCtxFunc = initCtxFunc
		frameworkConfig.Logger = config.Logger
		frameworkConfig.ResourceRouter = framework.DefaultResourceRouter(resources)
		frameworkConfig.TPR = newTPR

		customObjectFramework, err = framework.New(frameworkConfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	return customObjectFramework, nil
}