package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}
var cveResponse = new(cveResponseTemplate)

func getJSON(cve string, target interface{}) error {
	url := "https://services.nvd.nist.gov/rest/json/cve/1.0/"
	cveurl := url + cve
	r, err := httpClient.Get(cveurl)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

//TODO
//func options() {
//	cweFlag := flag.Bool("cwe", false, "Display CWE")
//	cveFlag := flag.Bool("cve", false, "Display CVE")
//
//	flag.Parse()
//
//}

func printInfo() {
	cve := cveResponse.Result.CVEItems[0].Cve.CVEDataMeta.ID
	nvdCwe := cveResponse.Result.CVEItems[0].Cve.Problemtype.ProblemtypeData[0].Description[0].Value
	cnaCwe := cveResponse.Result.CVEItems[0].Cve.Problemtype.ProblemtypeData[0].Description[1].Value
	cvss3Score := cveResponse.Result.CVEItems[0].Impact.BaseMetricV3.CvssV3.BaseScore
	cvss3String := cveResponse.Result.CVEItems[0].Impact.BaseMetricV3.CvssV3.VectorString
	publishedDate := cveResponse.Result.CVEItems[0].PublishedDate
	description := cveResponse.Result.CVEItems[0].Cve.Description.DescriptionData[0].Value

	fmt.Printf("\nCVE: %+v\n", cve)
	fmt.Printf("NVD CWE: %+v\n", nvdCwe)
	fmt.Printf("CNA CWE: %+v\n", cnaCwe)
	fmt.Printf("CVSS3: %+v/%+v\n", cvss3Score, cvss3String)
	fmt.Printf("Public Date: %+v\n", publishedDate)
	fmt.Printf("Description: \n\n %+v\n\n", description)

}
