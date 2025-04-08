package registrar

import (
	"database/sql"
	"github.com/franc-zar/k8s-node-attestation/pkg/cluster"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	_ "modernc.org/sqlite"
	"os"
	"os/signal"
	"syscall"
)

type Registrar struct {
	interactor           cluster.Interactor
	informerFactory      informers.SharedInformerFactory
	attestationDadatabse AttestationDatabase
}

func (r *Registrar) deleteNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)
}

func (r *Registrar) addNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)
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

	// Keep running until stopped
	<-stopStructCh
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
