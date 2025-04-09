package registrar

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/cluster"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"github.com/veraison/cmw"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Registrar struct {
	interactor          cluster.Interactor
	informerFactory     informers.SharedInformerFactory
	attestationDatabase AttestationDatabase
	defaultResync       int
	dataSourceName      string
}

func (r *Registrar) Init(defaultResync int, dataSourceName string) {
	r.interactor.ConfigureKubernetesClient()
	r.informerFactory = informers.NewSharedInformerFactory(r.interactor.ClientSet, time.Minute*time.Duration(defaultResync))
	r.attestationDatabase.Open(dataSourceName)
	r.attestationDatabase.Init()
}

func (r *Registrar) deleteNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)
	r.unregisterNode(node)
}

func (r *Registrar) addNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)
	r.registerNode(node)
}

func (r *Registrar) WatchNodes() {
	stopCh := setupSignalHandler()
	nodeInformer := r.informerFactory.Core().V1().Nodes().Informer()

	nodeEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    r.addNodeHandling,
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: r.deleteNodeHandling,
	}

	// Add event handlers for Node events
	_, err := nodeInformer.AddEventHandler(nodeEventHandler)
	if err != nil {
		logger.Fatal("failed to create node event handler: %v", err)
	}

	// Convert `chan os.Signal` to `<-chan struct{}`
	stopStructCh := make(chan struct{})
	go func() {
		<-stopCh // Wait for signal
		close(stopStructCh)
	}()

	// Start the informer
	go nodeInformer.Run(stopStructCh)

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(stopStructCh, nodeInformer.HasSynced) {
		logger.Warning("Timed out waiting for caches to sync")
		return
	}
	<-stopStructCh
	defer r.attestationDatabase.Close()
}

func (r *Registrar) registerNode(node *corev1.Node) {

}

func (r *Registrar) unregisterNode(node *corev1.Node) {
	nodeUID := string(node.GetUID())
	nodeName := node.GetName()

	err := r.attestationDatabase.DeleteWorker(nodeUID)
	if err != nil {
		logger.Error("Failed to delete worker node '%s' from attestation database: %v", nodeUID, err)
		return
	}
	logger.Success("Deleted worker node '%s' from attestation database", nodeUID)

	err = r.interactor.DeleteAgent(nodeName)
	if err != nil {
		logger.Error("Failed to delete agent from worker node '%s': %v", nodeUID, err)
		return
	}
	logger.Success("Deleted agent from worker node '%s'", nodeUID)
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
