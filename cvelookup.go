package main

import (
	"os"
	"strings"
)

func main() {
	for i := 1; i <= len(os.Args[1:]); i++ {
		cve := os.Args[i]
		if (strings.Contains("-", cve)) == true {
			continue

		}
		getJSON(cve, cveResponse)
		printInfo()
		cveResponse = new(cveResponseTemplate)

	}

}
