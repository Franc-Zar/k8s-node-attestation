package registrar

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/registrar"
	"os"
)

func main() {
	registrar.CLI(os.Args)
}
