package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/fatih/color"
)

type Response struct {
	IfExistsResult      int
	NameSpaceType       string `json:"NameSpaceType"`
	DomainName          string `json:"DomainName"`
	AuthURL             string `json:"AuthURL"`
	CloudInstanceName   string `json:"CloudInstanceName"`
	FederationBrandName string `json:"FederationBrandName"`
}

var response Response
var tenant string

func doUserEnumCredType(username, cloud string) {

	requestBody := map[string]string{"Username": username}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		doError(color.RedString("Error marshaling JSON: " + err.Error()))
	}

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", "https://login.microsoftonline."+cloud+"/common/GetCredentialType", bytes.NewBuffer(jsonBody))
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36")

	if err != nil {
		doError(color.RedString("Error creating request: " + err.Error()))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		doError(color.RedString("Error sending request: " + err.Error()))
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		doError(color.RedString("Error reading response: " + err.Error()))
	}
	// Unmarshal the JSON response into the Response struct
	if err := json.Unmarshal(body, &response); err != nil {
		doError(color.RedString("Error unmarshaling JSON: " + err.Error()))
	}

	res_status := ""

	if response.IfExistsResult == 0 {
		res_status = color.GreenString("[+] Valid user : " + username)
	} else {
		res_status = color.RedString("[-] Invalid user :" + username)
	}
	log.Println(res_status)
	doWritefile(res_status)
}

func douserEnumOneDrive(user string) {
	url := fmt.Sprintf("https://%s-my.sharepoint.com/personal/%s/_layouts/15/onedrive.aspx", tenant, strings.ReplaceAll(strings.ReplaceAll(strings.Split(user, "@")[0], ".", "_"), "-", "_"))
	resp, err := http.Head(url)

	if err != nil {
		doError(color.RedString("Error making request: " + err.Error()))
	}
	defer resp.Body.Close()

	if err == nil && slices.Contains([]int{200, 401, 403, 302}, resp.StatusCode) {
		res_status := color.GreenString("[+] Confirmed valid " + user + " (Response code " + resp.Status + ")")
		log.Println(res_status)
		doWritefile(res_status)
		return
	}
	log.Println(color.RedString("[-] Invalid user : " + user))

}

func doTenantOneDrive(tenant, domain string) string {
	url := fmt.Sprintf("https://%s-my.sharepoint.com/personal/TESTUSER_%s/_layouts/15/onedrive.aspx", tenant, strings.ReplaceAll(domain, ".", "_"))
	fmt.Println(url)
	resp, err := http.Head(url)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		fmt.Printf("Tenant \"%s\" confirmed via OneDrive: %s", tenant, url)
		os.Exit(0)
		return tenant
	}
	fmt.Println("Hosted OneDrive instance for " + tenant + " does not exist")
	return ""
}

func doGetTenantDomain(domain string) {

	uri := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
	body := (`<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Request>
                    <Domain>` + domain + `</Domain>
                </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
    </soap:Envelope>`)

	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(body))
	if err != nil {
		doError("failed to create request:", err.Error())
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		doError(err.Error())
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		doError("failed to read response body: %w", err.Error())
	}
	println(string(responseBody))
	os.Exit(0)
	// Use regex to find domains
	re := regexp.MustCompile(`<Domain>([^<]*)</Domain>`)
	matches := re.FindAllStringSubmatch(string(responseBody), -1)
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], ".onmicrosoft.com") {
			tenant = doTenantOneDrive(strings.ReplaceAll(match[1], ".onmicrosoft.com", ""), domain)
			if tenant != "" {
				return
			}
		}
	}

	fmt.Println("no domain with onmicrosoft.com suffix found")
}

func doUser(usernameList []string, domain, cloud string) {
	// if_exists_result_codes := map[int]string{
	// 	-1: "UNKNOWN_ERROR",
	// 	0:  "VALID_USERNAME",
	// 	1:  "UNKNOWN_USERNAME",
	// 	2:  "THROTTLE",
	// 	4:  "ERROR",
	// 	5:  "VALID_USERNAME_DIFFERENT_IDP",
	// 	6:  "VALID_USERNAME",
	// }

	fmt.Println(color.CyanString("[i] Starting User enumeration\n"))
	fmt.Println(color.CyanString("[i] Using https://login.microsoftonline." + cloud + "/common/GetCredentialType to verify emails\n"))

	doGetTenantDomain(domain)

	resp, err := http.Get("https://login.microsoftonline." + cloud + "/getuserrealm.srf?login=user@" + domain)
	if err != nil {
		doError(color.GreenString("Error making request " + err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		doError(color.GreenString("Error reading response body: " + err.Error()))
	}

	if err := json.Unmarshal(body, &response); err != nil {
		doError(color.GreenString("Error unmarshaling JSON: " + err.Error()))
	}

	fmt.Println(color.GreenString("[+] FederationBrandName : " + response.FederationBrandName))
	fmt.Println(color.GreenString("[+] DomainName          : " + response.DomainName))
	fmt.Println(color.GreenString("[+] CloudInstanceName   : " + response.CloudInstanceName))
	fmt.Println(color.GreenString("[+] NameSpaceType       : " + response.NameSpaceType))
	fmt.Println(color.GreenString("[+] AuthURL             : " + response.AuthURL + "\n\n"))

	if response.NameSpaceType == "Unknown" {
		doError(color.HiRedString("Looks like the domain is not part of the microsoft tenet. If you are sure try different CloudInstanceName"))
	}

	for _, username := range usernameList {

		// Build a logic to use different endpoints based on the user input
		doUserEnumCredType(username, cloud)
		// douserEnumOneDrive(username)

	}
}
