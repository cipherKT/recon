package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/utils"
)

func RunProbe(cfg config.Config) error {
	// httpx
	done := make(chan bool)
	go utils.Spinner("Running httpx...", done)
	httpxFile := cfg.Output + "/httpx_alive.txt"
	httpx := exec.Command("httpx", "-l", cfg.Output+"/all.txt", "-status-code", "-title", "-location", "-tech-detect", "-ip", "-web-server", "-content-length", "-o", httpxFile)
	httpx.Stdout = os.Stdout
	httpx.Stderr = os.Stderr
	httpxErr := httpx.Run()
	done <- true
	if httpxErr != nil {
		return fmt.Errorf("httpx failed\n%w", httpxErr)
	}
	// Clearing the output
	err := utils.ExtractUrls(httpxFile, cfg.Output+"/httpx_urls.txt")
	if err != nil {
		return fmt.Errorf("Failed to extract URLs in httpx results\n%w", err)
	}

	return nil
}
