package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/utils"
)

func RunCrawl(cfg config.Config) error {
	// running katana
	done := make(chan bool)
	go utils.Spinner("Running katana....", done)
	katanaFile := cfg.Output + "/katana_urls.txt"
	katana := exec.Command("katana", "-list", cfg.Output+"/httpx_urls.txt", "-d", "3", "-jc", "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,webm", "-o", katanaFile)
	katana.Stdout = os.Stdout
	katana.Stderr = os.Stderr
	katanaErr := katana.Run()
	done <- true
	if katanaErr != nil {
		return fmt.Errorf("Katana failed!\n%w", katanaErr)
	}

	// running hakrawler
	done = make(chan bool)
	go utils.Spinner("running hakrawler....", done)
	inputFile, err := os.Open(cfg.Output + "/httpx_urls.txt")
	if err != nil {
		return fmt.Errorf("could not open httpx_urls.txt\n%w", err)
	}
	defer inputFile.Close()

	hakrawler := exec.Command("hakrawler", "-depth", "2", "-plain")
	hakrawlerFile, err := os.Create(cfg.Output + "/hakrawler_urls.txt")
	if err != nil {
		return fmt.Errorf("could not create hakrawler ouput file\n%w", err)
	}
	defer hakrawlerFile.Close()
	hakrawler.Stdin = inputFile
	hakrawler.Stdout = hakrawlerFile
	hakrawler.Stderr = os.Stderr
	hakrawlerErr := hakrawler.Run()
	done <- true
	if hakrawlerErr != nil {
		return fmt.Errorf("hakrawler failed! \n%w", hakrawlerErr)
	}

	// merging results
	done = make(chan bool)
	go utils.Spinner("merging results of crawler...", done)
	files := []string{
		katanaFile,
		hakrawlerFile.Name(),
	}
	mergeFile := cfg.Output + "/crawl_results.txt"
	err = utils.MergeFiles(mergeFile, files)
	done <- true
	if err != nil {
		return fmt.Errorf("failed to merge crawled results\n%w", err)
	}

	return nil
}
