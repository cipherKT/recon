package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/utils"
)

func RunPassive(cfg config.Config) error {
	// Running subfinder
	done := make(chan bool)
	go utils.Spinner("running subfinder...", done)
	subfinderFile := cfg.Output + "/subfinder_subs.txt"
	subfinder := exec.Command("subfinder", "-d", cfg.Domain, "--silent", "--recursive", "--all", "-o", subfinderFile)
	subfinder.Stdout = os.Stdout
	subfinder.Stderr = os.Stderr
	subfinderErr := subfinder.Run()
	if subfinderErr != nil {
		return fmt.Errorf("subfinder failed! \n%w", subfinderErr)
	}
	done <- true

	// Running assetfinder
	done = make(chan bool)
	go utils.Spinner("running assetfinder...", done)
	assetfinder := exec.Command("assetfinder", "--subs-only", cfg.Domain)
	assetfinderFile, err := os.Create(cfg.Output + "/assetfinder_subs.txt")
	if err != nil {
		return fmt.Errorf("could not create assetfinder output file: %w", err)
	}
	defer assetfinderFile.Close()
	assetfinder.Stdout = assetfinderFile
	assetfinder.Stderr = os.Stderr
	assetfinderErr := assetfinder.Run()
	if assetfinderErr != nil {
		return fmt.Errorf("assetfinder failed! \n%w", assetfinderErr)
	}
	done <- true

	// Running amass
	done = make(chan bool)
	go utils.Spinner("running amass...", done)
	amassFile := cfg.Output + "/amass_passive_subs.txt"
	amass := exec.Command("amass", "enum", "-passive", "-d", cfg.Domain, "-o", amassFile)
	amass.Stderr = os.Stderr
	amassErr := amass.Run()
	if amassErr != nil {
		return fmt.Errorf("amass failed! \n%w", amassErr)
	}
	done <- true

	// Querying crt.sh
	done = make(chan bool)
	go utils.Spinner("querying crt.sh...", done)
	Query_url := "https://crt.sh/?q=%." + cfg.Domain + "&output=json"
	resp, err := http.Get(Query_url)
	if err != nil {
		return fmt.Errorf("request to crt.sh failed\n%w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read crt.sh body\n%w", err)
	}
	var results []struct {
		Name string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &results); err != nil {
		return fmt.Errorf("failed to parse crt.sh response\n%w", err)
	}
	crtshFile, err := os.Create(cfg.Output + "/crtsh_subs.txt")
	if err != nil {
		return fmt.Errorf("could not create crt.sh output file: %w", err)
	}
	defer crtshFile.Close()
	for _, r := range results {
		fmt.Fprintln(crtshFile, r.Name)
	}
	done <- true

	// Gathering subdomains from GitHub
	if cfg.GitHub_token != "" {
		done = make(chan bool)
		go utils.Spinner("querying github...", done)
		_, err := exec.LookPath("github-subdomains")
		if err != nil {
			return fmt.Errorf("github-subdomains is not installed")
		}
		githubFile := cfg.Output + "/github_subs.txt"
		github := exec.Command("github-subdomains", "-d", cfg.Domain, "-t", cfg.GitHub_token, "-o", githubFile)
		github.Stderr = os.Stderr
		githubErr := github.Run()
		if githubErr != nil {
			return fmt.Errorf("github-subdomains failed! \n%w", githubErr)
		}
		done <- true
	}

	// Merging results
	done = make(chan bool)
	go utils.Spinner("merging results...", done)
	files := []string{
		subfinderFile,
		assetfinderFile.Name(),
		amassFile,
		crtshFile.Name(),
	}
	if cfg.GitHub_token != "" {
		files = append(files, cfg.Output+"/github_subs.txt")
	}
	allSubsFile := cfg.Output + "/all_subs.txt"
	err = utils.MergeFiles(allSubsFile, files)
	if err != nil {
		return fmt.Errorf("failed to merge files\n%w", err)
	}
	done <- true

	return nil
}
