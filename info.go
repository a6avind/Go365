package main

import (
	"fmt"

	"github.com/fatih/color"
)

const (
	version = "2.0"
	tool    = "Go365"
	authors = "paveway3, h0useh3ad, S4R1N, EatonChips"
	usage   = `Usage:
  -h                            Shows this stuff
  Required - Endpoint:			
    -endpoint [rst or graph]    Specify which endpoint to use
								                : (-endpint user)    https://login.microsoftonline.com/common/GetCredentialType. HTTP POST request with JSON Response
                                : (-endpoint rst)   *Classic Go365!* login.microsoftonline.com/rst2.srf. SOAP XML request with XML response
                                : (-endpoint graph)  login.microsoft.com/common/oauth2/token. HTTP POST request with JSON Response
  Required - Usernames and Passwords:
    -u <string>                 Single username to test
                                : Username with or without "@domain.com"
                                : Must also provide -d flag to specify the domain
                                : (-u legitfirst.lastname@totesrealdomain.com)
    -ul <file>                  Username list to use (overrides -u)
                                : File should contain one username per line
                                : Usernames can have "@domain.com"
                                : If no domain is specified, the -d domain is used
                                : (-ul ./usernamelist.txt)
    -p <string>                 Password to attempt
                                : Enclose in single quotes if it contains special characters
                                : (-p password123)  or  (-p 'p@s$w0|2d')
    -pl <file>                  Password list to use (overrides -p)
                                : File should contain one password per line
                                : -delay flag can be used to include a pause between each set of attempts
                                : (-pl ./passwordlist.txt)
    -up <file>                  Userpass list to use (overrides all the above options)
                                : One username and password separated by a ":" per line
                                : Be careful of duplicate usernames!
                                : (-up ./userpasslist.txt)
  Required - Domain:
    -d <string>                 Domain to test
                                : Use this if the username or username list does not include "@targetcompany.com"
                                : (-d targetcompany.com)
  Optional:
    -w <int>                    Time to wait between attempts in seconds. 
                                : Default: 1 second. 5 seconds recommended.
                                : (-w 10)
    -delay <int>                Delay (in seconds) between sprays when using a password list.
                                : Default: 60 minutes (3600 seconds) recommended.
                                : (-delay 7200)
    -o <string>                 Output file to write to
                                : Will append if file exists, otherwise a file is created
                                : (-o ./Go365output.out)
    -proxy <string>             Single SOCKS5 proxy server to use
                                : IP address and Port separated by a ":"
                                : SOCKS5 proxy
                                : (-proxy 127.0.0.1:1080)
    -proxyfile <string>         A file with a list of SOCKS5 proxy servers to use
                                : IP address and Port separated by a ":" on each line
                                : Randomly selects a proxy server to use before each request
                                : (-proxyfile ./proxyfile.txt)
    -url <string>               Endpoint to send requests to
                                : Amazon API Gateway 'Invoke URL'
                                : Highly recommended that you use this option. Google it, or
                                : check this out: https://bigb0sss.github.io/posts/redteam-rotate-ip-aws-gateway/
                                : (-url https://notrealgetyourown.execute-api.us-east-2.amazonaws.com/login)
    -debug                      Debug mode.
                                : Print xml response
	  -cloud				          		: When spraying companies attached to US Tenants (https://login.microsoftonline.us/)
    -fireprox                   : Use AWS API Gateway to rotate IPs

 Examples:
  ./Go365 -endpoint user -ul ./user_list.txt -d pwnthisfakedomain.com -o valid_users.txt
  ./Go365 -endpoint rst -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com
  ./Go365 -endpoint graph -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5
  ./Go365 -endpoint rst -up ./userpass_list.txt -delay 3600 -d pwnthisfakedomain.com -w 5 -o Go365output.txt
  ./Go365 -endpoint graph -u legituser -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxy 127.0.0.1:1080
  ./Go365 -endpoint rst -u legituser -pl ./pass_list.txt -delay 1800 -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxyfile ./proxyfile.txt
  ./Go365 -endpoint graph -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -url https://notrealgetyourown.execute-api.us-east-2.amazonaws.com/login 
  You can even schedule out your entire password guessing campaign using the -pl and -delay flags :)
  ./Go365 -endpoint rst -ul ./user_list.txt -d pwnthisfakedomain.com -w 5 -o Go365output.txt -url https://notrealgetyourown.execute-api.us-east-2.amazonaws.com/login -proxyfile listofprox.txt -pl listofpasswords.txt -delay 7200
  
  *Protip: If you get a lot of "Account locked out" responses, then you might wanna proxy or use an AWS Gateway.`

	banner = `
  ██████         ██████   ██████  ██████
 ██                   ██ ██       ██
 ██  ███   ████   █████  ███████  ██████
 ██    ██ ██  ██      ██ ██    ██      ██
  ██████   ████  ██████   ██████  ██████
`
)

func info() {
	fmt.Println(color.BlueString(banner))
	fmt.Println(color.RedString(" Version: ") + version)
	fmt.Println(color.RedString(" Authors: ") + authors + "\n")
}
