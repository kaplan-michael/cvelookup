package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func printCwes() {
	Cwe := ("CWE not assigned")
	for i := 0; i < len(cveResponse.Result.CVEItems[0].Cve.Problemtype.ProblemtypeData[0].Description); i++ {

		Cwe = cveResponse.Result.CVEItems[0].Cve.Problemtype.ProblemtypeData[0].Description[i].Value
		fmt.Printf("CWE: %+v\n", Cwe)
	}
}

func printInfo() {

	if len(cveResponse.Result.CVEItems) <= 0 {
		err := fmt.Errorf("CVE was not found")
		fmt.Println(err.Error())
		os.Exit(1)

	}
	cve := cveResponse.Result.CVEItems[0].Cve.CVEDataMeta.ID
	//	Cwes := ("CWE not assigned")
	//	if len(cveResponse.Result.CVEItems[0].Cve.Problemtype.ProblemtypeData[0].Description) >= 0 {
	//		Cwes = cveResponse.Result.CVEItems[0].Cve.Problemtype.ProblemtypeData[0].Description[0:]
	//	}
	cvss3Score := cveResponse.Result.CVEItems[0].Impact.BaseMetricV3.CvssV3.BaseScore
	cvss3String := cveResponse.Result.CVEItems[0].Impact.BaseMetricV3.CvssV3.VectorString
	publishedDate := cveResponse.Result.CVEItems[0].PublishedDate
	description := cveResponse.Result.CVEItems[0].Cve.Description.DescriptionData[0].Value

	fmt.Printf("\nCVE: %+v\n", cve)
	//fmt.Printf("CWEs: %+v\n", Cwes)
	printCwes()
	fmt.Printf("CVSS3: %+v/%+v\n", cvss3Score, cvss3String)
	fmt.Printf("Public Date: %+v\n", publishedDate)
	fmt.Printf("Description: \n\n %+v\n\n", description)

}
