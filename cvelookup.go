package main

import (
	"os"
)

func main() {
	for i := 1; i <= len(os.Args[1:]); i++ {
		cve := os.Args[i]
		getJSON(cve, cveResponse)
		printInfo()
		cveResponse = new(cveResponseTemplate)

	}

}
