package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/utils"
)

func RunActive(cfg config.Config) error {
	// Running ShuffleDNS
	done := make(chan bool)
	go utils.Spinner("Downloding resolvers for shuffledns...", done)
	resolversFile := cfg.Output + "/resolvers.txt"
	err := utils.DownloadFile("https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt", resolversFile)
	if err != nil {
		return fmt.Errorf("Failed in downloading resolvers\n%w", err)
	}
	done <- true
	done = make(chan bool)
	go utils.Spinner("running shuffleDNS...", done)
	shuffleDNSFile := cfg.Output + "/active_subs.txt"
	shuffleDNS := exec.Command("shuffledns", "-d", cfg.Domain, "-list", cfg.Output+"/all_subs.txt", "-r", resolversFile, "-mode", "resolve", "-o", shuffleDNSFile)
	shuffleDNS.Stdout = os.Stdout
	shuffleDNS.Stderr = os.Stderr
	shuffleDNSErr := shuffleDNS.Run()
	if shuffleDNSErr != nil {
		return fmt.Errorf("shuffle dns failed!\n%w", shuffleDNSErr)
	}
	done <- true

	//Running Alterx
	done = make(chan bool)
	go utils.Spinner("Running Alterx", done)
	alterXFile := cfg.Output + "/alterx_subs.txt"
	alterX := exec.Command("alterx", "-l", shuffleDNSFile, "-o", alterXFile)
	alterX.Stdout = os.Stdout
	alterX.Stderr = os.Stderr
	alterXErr := alterX.Run()
	if alterXErr != nil {
		return fmt.Errorf("alterx failed!\n%w", alterXErr)
	}
	done <- true

	// Running DNSX
	done = make(chan bool)
	go utils.Spinner("Running DNSX", done)
	dnsxFile := cfg.Output + "/all.txt"
	dnsX := exec.Command("dnsx", "-l", alterXFile, "-resp", "-o", dnsxFile)
	dnsX.Stdout = os.Stdout
	dnsX.Stderr = os.Stderr
	dnsXErr := dnsX.Run()
	if dnsXErr != nil {
		return fmt.Errorf("dnsX failed!\n%w", dnsXErr)
	}
	done <- true

	return nil
}
