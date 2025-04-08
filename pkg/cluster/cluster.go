package cluster

import (
	"context"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/logger"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"strconv"
	//"github.com/franc-zar/k8s-node-attestation/logger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
)

type Interactor struct {
	ClientSet     *kubernetes.Clientset
	DynamicClient dynamic.Interface
}

const (
	ControlPlaneLabel          = "node-role.kubernetes.io/control-plane"
	AttestationNamespace       = "attestation-system"
	AgentServicePort     int32 = 9090
)

func (i *Interactor) DeleteNode(nodeName string) (bool, error) {
	// Delete the node
	err := i.ClientSet.CoreV1().Nodes().Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
	if err != nil {
		return false, fmt.Errorf("error deleting node '%s': %v", nodeName, err)
	}
	return true, nil
}

// NodeIsControlPlane check if node being considered is Control Plane; if node is already available just check for the control plane label presence, otherwise fetch the node
// with provided name
func (i *Interactor) NodeIsControlPlane(nodeName string, node *corev1.Node) (bool, error) {
	var err error
	if node == nil {
		node, err = i.ClientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to get node: %v", err)
		}
	}
	_, exists := node.Labels[ControlPlaneLabel]
	return exists, nil
}

// ConfigureKubernetesClient initializes the Kubernetes client by retrieving the kubeconfig file from home directory of current user under /.kube/config
func (i *Interactor) ConfigureKubernetesClient() {
	var err error
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logger.Fatal("Failed to build config from kubeconfig: %v", err)
		}
	}
	i.DynamicClient, err = dynamic.NewForConfig(config)
	if err != nil {
		logger.Fatal("Failed to create Kubernetes dynamic client: %v", err)
	}
	i.ClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		logger.Fatal("Failed to create Kubernetes client: %v", err)
	}
}

func (i *Interactor) DeleteAgent(workerName string) error {
	deploymentName := fmt.Sprintf("agent-%s-deployment", workerName)
	serviceName := fmt.Sprintf("agent-%s-service", workerName)

	// Delete the Service
	err := i.ClientSet.CoreV1().Services(AttestationNamespace).Delete(context.TODO(), serviceName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete Agent service '%s': %v", serviceName, err)
	}

	// Delete the Deployment
	err = i.ClientSet.AppsV1().Deployments(AttestationNamespace).Delete(context.TODO(), deploymentName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete Agent deplooyment '%s': %v", deploymentName, err)
	}
	return nil
}

func (i *Interactor) GetWorkerInternalIP(worker *corev1.Node) (string, error) {
	// Loop through the addresses of the node to find the InternalIP (within the cluster)
	var workerIP string
	for _, address := range worker.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			workerIP = address.Address
			break
		}
	}
	if workerIP == "" {
		return "", fmt.Errorf("no internal IP found for node '%s'", worker.GetName())
	}
	return workerIP, nil
}

func (i *Interactor) DeployAgent(newWorker *corev1.Node, agentConfig *model.AgentConfig) (bool, string, string, int, error) {
	agentReplicas := int32(1)
	privileged := true
	charDeviceType := corev1.HostPathCharDev
	pathFileType := corev1.HostPathFile
	agentDeploymentName := fmt.Sprintf("agent-%s-deployment", newWorker.GetName())
	agentContainerName := fmt.Sprintf("agent-%s", newWorker.GetName())
	agentServiceName := fmt.Sprintf("agent-%s-service", newWorker.GetName())

	agentHost, err := i.GetWorkerInternalIP(newWorker)
	if err != nil {
		return false, "", "", -1, fmt.Errorf("failed to get node '%s' internal IP address: %v", newWorker.GetName(), err)
	}

	agentNodePort := agentConfig.AgentNodePortAllocation

	// Define the Deployment
	agentDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentDeploymentName,
			Namespace: AttestationNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &agentReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "agent",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "agent",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  agentContainerName,
							Image: agentConfig.ImageName,
							Env: []corev1.EnvVar{
								{Name: "AGENT_PORT", Value: strconv.Itoa(int(agentConfig.AgentPort))},
								{Name: "TPM_PATH", Value: agentConfig.TPMPath},
							},
							Ports: []corev1.ContainerPort{
								{ContainerPort: agentConfig.AgentPort},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "tpm-device", MountPath: agentConfig.TPMPath},
								{Name: "ima-measurements", MountPath: agentConfig.IMAMountPath, ReadOnly: true},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "tpm-device",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: agentConfig.TPMPath,
									Type: &charDeviceType,
								},
							},
						},
						{
							Name: "ima-measurements",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: agentConfig.IMAMeasurementLogPath,
									Type: &pathFileType,
								},
							},
						},
					}, // Ensure pod is deployed on the new worker node
					NodeSelector: map[string]string{
						"kubernetes.io/hostname": newWorker.GetName(),
					},
				},
			},
		},
	}

	// Define the Service
	agentService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentServiceName,
			Namespace: AttestationNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "agent",
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       AgentServicePort,
					TargetPort: intstr.FromInt32(AgentServicePort),
					NodePort:   agentNodePort,
				},
			},
			Type: corev1.ServiceTypeNodePort,
		},
	}

	// Deploy the Deployment
	agentDeployment, err = i.ClientSet.AppsV1().Deployments(AttestationNamespace).Create(context.TODO(), agentDeployment, metav1.CreateOptions{})
	if err != nil {
		return false, "", "", -1, fmt.Errorf("error creating agent deployment '%s': %v", agentDeploymentName, err)
	}

	// Deploy the Service
	_, err = i.ClientSet.CoreV1().Services(AttestationNamespace).Create(context.TODO(), agentService, metav1.CreateOptions{})
	if err != nil {
		delErr := i.ClientSet.AppsV1().Deployments(AttestationNamespace).Delete(context.TODO(), agentDeployment.GetName(), metav1.DeleteOptions{})
		if delErr != nil {
			return false, "", "", -1, fmt.Errorf("error creating agent service '%s': %v; error deleting agent deployment '%s': %v", agentService.Name, err, agentDeployment.Name, delErr)
		}
		return false, "", "", -1, fmt.Errorf("error creating agent service '%s': %v", agentService.GetName(), err)
	}

	agentConfig.AgentNodePortAllocation += 1
	return true, agentDeployment.GetName(), agentHost, int(agentNodePort), nil
}
