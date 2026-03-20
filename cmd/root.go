package cmd

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/runner"
	"github.com/cipherKT/recon/utils"
	"github.com/spf13/cobra"
)

func banner() {
	fmt.Println(`
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝`)
	fmt.Println("    automated recon pipeline  ~cipherKT")
}

var rootCmd = &cobra.Command{
	Use:   "recon",
	Short: "Automation for recon \n \t\t ~cipher",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		banner()
	},
	Run: func(cmd *cobra.Command, args []string) {
		domain, _ := cmd.Flags().GetString("domain")
		output, _ := cmd.Flags().GetString("output")
		githubToken, _ := cmd.Flags().GetString("github-token")
		threads, _ := cmd.Flags().GetInt("threads")

		cfg := config.Config{
			Domain:       domain,
			Output:       output,
			Threads:      threads,
			GitHub_token: githubToken,
		}
		if cfg.Domain == "" {
			fmt.Println("Error: domain is required. Use -d target.com")
			return
		}
		err := utils.CheckTools(config.RequiredTools())
		if err != nil {
			fmt.Println(err)
			return
		}
		cfg.Output = cfg.Output + "/" + cfg.Domain + "_" + time.Now().Format("02-01-2006_15-04")
		mkdir_err := os.MkdirAll(cfg.Output, 0755)
		if mkdir_err != nil {
			fmt.Println("Error creating output directory", mkdir_err)
			return
		}
		startTime := time.Now()
		if cfg.GitHub_token == "" {
			cfg.GitHub_token = os.Getenv("GITHUB_TOKEN")
		}

		// passive scan
		err = runner.RunPassive(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}

		// active scan
		err = runner.RunActive(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}
		subzyChan := make(chan error, 1)
		go func() {
			subzyChan <- runner.RunTakeOver(cfg)
		}()

		// probing
		err = runner.RunProbe(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}

		// portscan + crawling
		var wg sync.WaitGroup
		errChan := make(chan error, 2)

		wg.Add(2)

		// portscan
		go func() {
			defer wg.Done()
			portScanErr := runner.RunPortScan(cfg)
			if portScanErr != nil {
				errChan <- portScanErr
			}
		}()

		// crawler
		go func() {
			defer wg.Done()
			crwalerErr := runner.RunCrawl(cfg)
			if crwalerErr != nil {
				errChan <- crwalerErr
				return
			}
			// Extract js files
			jsErr := utils.ExtractJsFiles(cfg.Output+"/crawl_results.txt", cfg.Output+"/js_files.txt")
			if jsErr != nil {
				errChan <- jsErr
				return
			}
		}()

		wg.Wait()
		close(errChan)
		for err := range errChan {
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		// vuln scan
		err = runner.RunNuclei(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}

		// waiting for subzy to complete
		takeoverErr := <-subzyChan
		if takeoverErr != nil {
			fmt.Println("subzy failed: ", takeoverErr)
		}

		// Generating summary
		err = utils.GenerateSummary(cfg, startTime, takeoverErr)
		if err != nil {
			fmt.Println(err)
		}

	},
}

func Execute() {
	rootCmd.Execute()
}

func init() {
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, s []string) {
		banner()
		cmd.Usage()
	})
	rootCmd.Flags().StringP("domain", "d", "", "Target domain e.g. target.com")
	rootCmd.Flags().StringP("output", "o", "./results", "Output directory")
	rootCmd.Flags().StringP("github-token", "g", "", "GitHub token")
	rootCmd.Flags().IntP("threads", "t", 50, "Number of threads")

}
