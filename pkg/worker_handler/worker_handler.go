package worker_handler

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/cluster"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"github.com/franc-zar/k8s-node-attestation/pkg/registrar"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type WorkerHandler struct {
	interactor      cluster.Interactor
	informerFactory informers.SharedInformerFactory
}

func (w *WorkerHandler) Init(defaultResync int) {
	w.interactor.ConfigureKubernetesClient()
	w.informerFactory = informers.NewSharedInformerFactory(w.interactor.ClientSet, time.Minute*time.Duration(defaultResync))
}

func (w *WorkerHandler) deleteNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)
	w.unregisterNode(node)
}

func (w *WorkerHandler) addNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)
	w.registerNode(node)
}

func (w *WorkerHandler) WatchNodes() {
	stopCh := setupSignalHandler()
	nodeInformer := w.informerFactory.Core().V1().Nodes().Informer()

	nodeEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    w.addNodeHandling,
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: w.deleteNodeHandling,
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
}

func (w *WorkerHandler) registerNode(node *corev1.Node) {

	_, _, err := registrar.RegisterNodeCommand()
}

func (w *WorkerHandler) unregisterNode(node *corev1.Node) {
	nodeUID := string(node.GetUID())
	nodeName := node.GetName()

	_, _, err := registrar.UnregisterNodeCommand(nodeUID)
	if err != nil {
		logger.Error("Failed to delete worker node '%s' from Registrar database: %v", nodeUID, err)
		return
	}

	logger.Success("Deleted worker node '%s' from Registrar database", nodeUID)

	err = w.interactor.DeleteAgent(nodeName)
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
