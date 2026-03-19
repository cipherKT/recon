package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/cipherKT/recon/config"
	"github.com/cipherKT/recon/runner"
	"github.com/cipherKT/recon/utils"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "recon",
	Short: "Automation for recon \n \t\t ~cipher",
	Run: func(cmd *cobra.Command, args []string) {
		domain, _ := cmd.Flags().GetString("domain")
		output, _ := cmd.Flags().GetString("output")
		wordlist, _ := cmd.Flags().GetString("wordlist")
		githubToken, _ := cmd.Flags().GetString("github-token")
		threads, _ := cmd.Flags().GetInt("threads")

		cfg := config.Config{
			Domain:       domain,
			Output:       output,
			Wordlist:     wordlist,
			Threads:      threads,
			GitHub_token: githubToken,
		}
		if cfg.Domain == "" {
			fmt.Println("Error: domain is required. Use -d target.com")
			return
		}
		if cfg.Wordlist == "" {
			fmt.Println("Error: wordlist is required. Use -w /path/to/wordlist.txt")
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
		if cfg.GitHub_token == "" {
			cfg.GitHub_token = os.Getenv("GITHUB_TOKEN")
		}
		err = runner.RunPassive(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = runner.RunActive(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = runner.RunProbe(cfg)
		if err != nil {
			fmt.Println(err)
			return
		}

	},
}

func Execute() {
	rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringP("domain", "d", "", "Target domain e.g. target.com")
	rootCmd.Flags().StringP("output", "o", "./results", "Output directory")
	rootCmd.Flags().StringP("wordlist", "w", "", "Path to wordlist for ffuf")
	rootCmd.Flags().StringP("github-token", "g", "", "GitHub token")
	rootCmd.Flags().IntP("threads", "t", 50, "Number of threads")

}
