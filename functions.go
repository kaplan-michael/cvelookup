package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}
var cveResponse = new(cveResponseTemplate)

//Define flag vars
var refFlagShort *bool
var refFlag *bool

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

//print references if ref flag is given
func references() {
	//	cweFlag := flag.Bool("cwe", false, "Display CWE")
	//	cveFlag := flag.Bool("cve", false, "Display CVE")
	refFlag = flag.Bool("ref", false, "Display References")
	refFlagShort = flag.Bool("r", false, "Display References")
	flag.Parse()
	if *refFlag || *refFlagShort == true {

		references := cveResponse.Result.CVEItems[0].Cve.References.ReferenceData
		fmt.Printf("References: \n\n %+v\n\n", references)

	}

}

func printInfo() {

	if len(cveResponse.Result.CVEItems) <= 0 {
		err := fmt.Errorf("CVE was not found")
		fmt.Println(err.Error())
		os.Exit(1)

	}

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
	references()

}
