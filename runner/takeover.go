package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
)

func RunTakeOver(cfg config.Config) error {
	// subzy
	subzyFile := cfg.Output + "/takeover.txt"
	subzy := exec.Command("subzy", "run", "--targets", cfg.Output+"/all.txt", "--output", subzyFile)
	subzy.Stdout = os.Stdout
	subzy.Stderr = os.Stderr
	subzyErr := subzy.Run()
	if subzyErr != nil {
		return fmt.Errorf("subzy failed!\n%w", subzyErr)
	}

	return nil
}
