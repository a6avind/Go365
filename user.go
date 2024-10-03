package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
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

	tenant, err := doGetTenantDomain(domain)

	fmt.Println(tenant, err)
	os.Exit(0)
	resp, err := http.Get("https://login.microsoftonline." + cloud + "/getuserrealm.srf?login=user@" + domain)
	if err != nil {
		doError(color.GreenString("Error making request " + err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		doError(color.GreenString("Error reading response body: " + err.Error()))
	}

	var response Response
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

		requestBody := map[string]string{"Username": username}

		jsonBody, err := json.Marshal(requestBody)
		if err != nil {
			doError(color.RedString("Error marshaling JSON: " + err.Error()))
		}

		// Create a new HTTP POST request
		req, err := http.NewRequest("POST", "https://login.microsoftonline."+cloud+"/common/GetCredentialType", bytes.NewBuffer(jsonBody))
		if err != nil {
			doError(color.RedString("Error creating request: " + err.Error()))
		}
		req.Header.Set("Content-Type", "application/json")

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
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
		fmt.Println(res_status)
		doWritefile(res_status)
	}
}

func doGetTenantDomain(domain string) (string, error) {

	uri := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
			<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
						xmlns:a="http://schemas.microsoft.com/ws/2005/08/addressing">
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
							<Domain>%s</Domain>
						</Request>
					</GetFederationInformationRequestMessage>
				</soap:Body>
			</soap:Envelope>`, domain)

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation")

	client := &http.Client{}
	resp, err := client.Do(req)
	fmt.Println(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Use regex to find domains
	re := regexp.MustCompile(`<Domain>([^<]*)</Domain>`)
	matches := re.FindAllStringSubmatch(string(responseBody), -1)
	fmt.Println(matches)
	for _, match := range matches {
		if len(match) > 1 && strings.Contains(match[1], "onmicrosoft.com") {
			return match[1], nil
		}
	}

	return "", fmt.Errorf("no domain with onmicrosoft.com suffix found")
}
