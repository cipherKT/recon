package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/utils"
)

func RunNuclei(cfg config.Config) error {

	done := make(chan bool)
	go utils.Spinner("Running nuclei vulnerability scan...", done)
	nucleiFile := cfg.Output + "/nuclei_results.txt"
	nuclei := exec.Command("nuclei", "-l", cfg.Output+"/httpx_urls.txt", "-severity", "medium,high,critical", "-o", nucleiFile)
	nuclei.Stdout = os.Stdout
	nuclei.Stderr = os.Stderr
	nucleiErr := nuclei.Run()
	done <- true
	if nucleiErr != nil {
		return fmt.Errorf("nuclei failed!\n%w", nucleiErr)
	}
	return nil
}
