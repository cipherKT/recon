package utils

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cipherKT/recon/config"
)

func CheckTools(tools []string) error {
	missing := []string{}
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing tool %v", missing)
	}
	return nil
}

func MergeFiles(dest string, source []string) error {
	seen := map[string]bool{}
	for _, filePath := range source {
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			seen[line] = true
		}
	}

	destFile, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("could not create destination file \n%w", err)
	}
	defer destFile.Close()

	for line := range seen {
		fmt.Fprintln(destFile, line)
	}
	return nil
}

func Spinner(message string, done chan bool) {
	frames := []string{"[|]", "[/]", "[-]", "[\\]"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Printf("\r[*] %s\n", message)
			return
		default:
			fmt.Printf("\r%s %s", frames[i%4], message)
			time.Sleep(100 * time.Millisecond)
			i++
		}
	}
}

func DownloadFile(url string, outputPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("Failed to download file \n%w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read file body\n%w", err)
	}
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("Failed to create the output file \n%w", err)
	}
	defer outputFile.Close()
	outputFile.Write(body)

	return nil

}

func ExtractUrls(inputFile string, outputFile string) error {
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("Error opening the input file for URL extraction\n%w", err)
	}
	defer file.Close()
	urls := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			urls = append(urls, fields[0])
		}
	}
	op, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("Error creating the output file for URL extraction\n%w", err)
	}
	defer op.Close()
	for _, url := range urls {
		fmt.Fprintln(op, url)
	}
	return nil

}

func ExtractJsFiles(inputFile string, outputFile string) error {

	// reading files
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("Error opening input file for extracting js files\n%w", err)
	}
	defer file.Close()
	jsFiles := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasSuffix(scanner.Text(), ".js") {
			jsFiles = append(jsFiles, scanner.Text())
		}
	}

	// writing to output file
	op, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("Error creating the output file for Js file extraction\n%w", err)
	}
	defer op.Close()
	for _, file := range jsFiles {
		fmt.Fprintln(op, file)
	}
	return nil
}
func CountLines(filePath string) int {
	file, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func GenerateSummary(cfg config.Config, startTime time.Time, takeoverErr error) error {
	duration := time.Since(startTime).Round(time.Second)

	// count results from each phase
	subdomains := CountLines(cfg.Output + "/all_subs.txt")
	liveHosts := CountLines(cfg.Output + "/httpx_alive.txt")
	ports := CountLines(cfg.Output + "/ports.txt")
	crawledURLs := CountLines(cfg.Output + "/crawl_results.txt")
	jsFiles := CountLines(cfg.Output + "/js_files.txt")
	takeover := CountLines(cfg.Output + "/takeover.txt")
	nuclei := CountLines(cfg.Output + "/nuclei_results.txt")

	// create the summary file
	summaryFile, err := os.Create(cfg.Output + "/summary.md")
	if err != nil {
		return fmt.Errorf("could not create summary.md\n%w", err)
	}
	defer summaryFile.Close()

	w := bufio.NewWriter(summaryFile)

	// header
	fmt.Fprintf(w, "# Recon Summary — %s\n\n", cfg.Domain)
	fmt.Fprintf(w, "**Date:** %s\n", startTime.Format("02-01-2006 15:04"))
	fmt.Fprintf(w, "**Duration:** %s\n", duration)
	fmt.Fprintf(w, "**GitHub token used:** %v\n\n", cfg.GitHub_token != "")

	// results
	fmt.Fprintf(w, "## Results\n\n")
	fmt.Fprintf(w, "| Phase | Count | File |\n")
	fmt.Fprintf(w, "|-------|-------|------|\n")
	fmt.Fprintf(w, "| Subdomains collected | %d | [all_subs.txt](%s/all_subs.txt) |\n", subdomains, cfg.Output)
	fmt.Fprintf(w, "| Live hosts | %d | [httpx_alive.txt](%s/httpx_alive.txt) |\n", liveHosts, cfg.Output)
	fmt.Fprintf(w, "| Open ports | %d | [ports.txt](%s/ports.txt) |\n", ports, cfg.Output)
	fmt.Fprintf(w, "| Crawled URLs | %d | [crawl_results.txt](%s/crawl_results.txt) |\n", crawledURLs, cfg.Output)
	fmt.Fprintf(w, "| JS files | %d | [js_files.txt](%s/js_files.txt) |\n", jsFiles, cfg.Output)
	fmt.Fprintf(w, "| Takeover candidates | %d | [takeover.txt](%s/takeover.txt) |\n", takeover, cfg.Output)
	fmt.Fprintf(w, "| Nuclei findings | %d | [nuclei_results.txt](%s/nuclei_results.txt) |\n\n", nuclei, cfg.Output)

	// warnings if errors occurred
	if takeoverErr != nil {
		fmt.Fprintf(w, "> ⚠️ subzy encountered an error: %s\n\n", takeoverErr)
	}

	// next steps
	fmt.Fprintf(w, "## Next Steps\n\n")

	// always suggested
	fmt.Fprintf(w, "### 1. AI triage on httpx results\n")
	fmt.Fprintf(w, "Feed [httpx_alive.txt](%s/httpx_alive.txt) into AI to prioritize targets for bug hunting.\n\n", cfg.Output)

	fmt.Fprintf(w, "### 2. Archive enumeration\n")
	fmt.Fprintf(w, "Run the following on live hosts to find historical endpoints:\n")
	fmt.Fprintf(w, "```bash\n")
	fmt.Fprintf(w, "gau --subs %s | anew gau_results.txt\n", cfg.Domain)
	fmt.Fprintf(w, "waymore -i %s -mode U -oU waymore_results.txt\n", cfg.Domain)
	fmt.Fprintf(w, "waybackurls %s | anew wayback_results.txt\n", cfg.Domain)
	fmt.Fprintf(w, "```\n\n")

	fmt.Fprintf(w, "### 3. Parameter discovery on crawled URLs\n")
	fmt.Fprintf(w, "Run gf patterns on [crawl_results.txt](%s/crawl_results.txt) to find potential vuln parameters:\n", cfg.Output)
	fmt.Fprintf(w, "```bash\n")
	fmt.Fprintf(w, "cat %s/crawl_results.txt | gf sqli | anew sqli_params.txt\n", cfg.Output)
	fmt.Fprintf(w, "cat %s/crawl_results.txt | gf xss | anew xss_params.txt\n", cfg.Output)
	fmt.Fprintf(w, "cat %s/crawl_results.txt | gf lfi | anew lfi_params.txt\n", cfg.Output)
	fmt.Fprintf(w, "cat %s/crawl_results.txt | gf ssrf | anew ssrf_params.txt\n", cfg.Output)
	fmt.Fprintf(w, "cat %s/crawl_results.txt | gf redirect | anew redirect_params.txt\n", cfg.Output)
	fmt.Fprintf(w, "```\n\n")

	fmt.Fprintf(w, "### 4. JS file analysis\n")
	fmt.Fprintf(w, "Analyze [js_files.txt](%s/js_files.txt) for endpoints and secrets:\n", cfg.Output)
	fmt.Fprintf(w, "```bash\n")
	fmt.Fprintf(w, "cat %s/js_files.txt | while read url; do python3 linkfinder.py -i $url -o cli; done\n", cfg.Output)
	fmt.Fprintf(w, "cat %s/js_files.txt | while read url; do python3 secretfinder.py -i $url -o cli; done\n", cfg.Output)
	fmt.Fprintf(w, "```\n\n")

	// conditional next steps based on results
	if ports > 0 {
		fmt.Fprintf(w, "### 5. Review non-standard ports\n")
		fmt.Fprintf(w, "Open ports were found. Check [ports.txt](%s/ports.txt) and manually review non-standard ports (8080, 8443, 9000, 3000 etc.) — these often run admin panels or staging services.\n\n", cfg.Output)
	}

	if takeover > 0 {
		fmt.Fprintf(w, "### 6. ⚠️ Subdomain takeover candidates found!\n")
		fmt.Fprintf(w, "%d potential takeover(s) detected. Review [takeover.txt](%s/takeover.txt) immediately and verify each one manually.\n\n", takeover, cfg.Output)
	}

	if nuclei > 0 {
		fmt.Fprintf(w, "### 7. ⚠️ Nuclei findings detected!\n")
		fmt.Fprintf(w, "%d finding(s) detected. Review [nuclei_results.txt](%s/nuclei_results.txt) and triage by severity. Create POCs for confirmed vulnerabilities.\n\n", nuclei, cfg.Output)
	}

	fmt.Fprintf(w, "### 8. Directory fuzzing (after prioritization)\n")
	fmt.Fprintf(w, "After AI triage, run ffuf on high priority targets:\n")
	fmt.Fprintf(w, "```bash\n")
	fmt.Fprintf(w, "ffuf -u https://TARGET/FUZZ -w /path/to/wordlist.txt -mc 200,403 -o ffuf_results.txt\n")
	fmt.Fprintf(w, "```\n\n")

	fmt.Fprintf(w, "### 9. Review 403 endpoints\n")
	fmt.Fprintf(w, "Check httpx results for 403 responses and attempt bypass techniques.\n\n")

	fmt.Fprintf(w, "---\n")
	fmt.Fprintf(w, "*Generated by recon — github.com/cipherKT/%s*\n", cfg.Domain)

	return w.Flush()
}
