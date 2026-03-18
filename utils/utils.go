package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"
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
