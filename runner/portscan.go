package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/utils"
)

func RunPortScan(cfg config.Config) error {

	// Running naabu
	done := make(chan bool)
	go utils.Spinner("Running naabu....", done)
	naabuFile := cfg.Output + "/ports.txt"
	naabu := exec.Command("naabu", "-list", cfg.Output+"/httpx_urls.txt", "-top-ports", "100", "-o", naabuFile)
	naabu.Stdout = os.Stdout
	naabu.Stderr = os.Stderr
	naabuErr := naabu.Run()
	done <- true
	if naabuErr != nil {
		return fmt.Errorf("naabu failed!\n%w", naabuErr)
	}

	return nil
}
