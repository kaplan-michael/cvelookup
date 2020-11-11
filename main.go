package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	"github.com/kaplan-michael/cve-lookup/template"
)

type Foo struct {
    Bar string
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func getJSON(cve string, target interface{}) error {
	url := &cve
	r, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

func main() {
	cveResponse = new cveResponseTemplate
	cve := os.Args[1]
	getJSON(cve, cveResponse)

	fmt.Print("test")

}
