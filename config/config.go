package config

type Config struct {
	Domain       string
	Output       string
	Wordlist     string
	Threads      int
	GitHub_token string
}

func RequiredTools() []string {
	return []string{
		"subfinder",
		"assetfinder",
		"amass",
		"shuffledns",
		"dnsx",
		"alterx",
		"httpx",
		"katana",
		"hakrawler",
		"naabu",
		"ffuf",
		"nuclei",
		"subzy",
	}
}
