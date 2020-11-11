package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func getJSON(cve string, target interface{}) error {
	url := "https://services.nvd.nist.gov/rest/json/cve/1.0/"
	cveurl := url + cve
	fmt.Println(cveurl)
	r, err := httpClient.Get(cveurl)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

func main() {
	cveResponse := new(cveResponseTemplate)
	cve := os.Args[1]
	getJSON(cve, cveResponse)

	fmt.Println(cveResponse.Result.CVEItems)

}
