package main

import (
	"encoding/base64"
	"fmt"
	"ntlm"
	"ntlm/messages"
)

func main() {
	challengeMessage := "TlRMTVNTUAACAAAAAAAAADgAAABVgphiPXSy0E6+HrMAAAAAAAAAAKIAogA4AAAABQEoCgAAAA8CAA4AUgBFAFUAVABFAFIAUwABABwAVQBLAEIAUAAtAEMAQgBUAFIATQBGAEUAMAA2AAQAFgBSAGUAdQB0AGUAcgBzAC4AbgBlAHQAAwA0AHUAawBiAHAALQBjAGIAdAByAG0AZgBlADAANgAuAFIAZQB1AHQAZQByAHMALgBuAGUAdAAFABYAUgBlAHUAdABlAHIAcwAuAG4AZQB0AAAAAAA="
	authenticateMessage := "TlRMTVNTUAADAAAAGAAYALYAAADSANIAzgAAADQANABIAAAAIAAgAHwAAAAaABoAnAAAABAAEACgAQAAVYKQQgUCzg4AAAAPYQByAHIAYQB5ADEAMgAuAG0AcwBnAHQAcwB0AC4AcgBlAHUAdABlAHIAcwAuAGMAbwBtAHUAcwBlAHIAcwB0AHIAZQBzAHMAMQAwADAAMAAwADgATgBZAEMAVgBBADEAMgBTADIAQwBNAFMAQQBPYrLjU4h0YlWZeEoNvTJtBQMnnJuAeUwsP+vGmAHNRBpgZ+4ChQLqAQEAAAAAAACPFEIFjx7OAQUDJ5ybgHlMAAAAAAIADgBSAEUAVQBUAEUAUgBTAAEAHABVAEsAQgBQAC0AQwBCAFQAUgBNAEYARQAwADYABAAWAFIAZQB1AHQAZQByAHMALgBuAGUAdAADADQAdQBrAGIAcAAtAGMAYgB0AHIAbQBmAGUAMAA2AC4AUgBlAHUAdABlAHIAcwAuAG4AZQB0AAUAFgBSAGUAdQB0AGUAcgBzAC4AbgBlAHQAAAAAAAAAAAANuvnqD3K88ZpjkLleL0NW"

	server, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
	server.SetUserInfo("userstress100008", "Welcome1", "")

	challengeData, _ := base64.StdEncoding.DecodeString(challengeMessage)
	c, _ := messages.ParseChallengeMessage(challengeData)

	fmt.Println("----- Challenge Message ----- ")
	fmt.Println(c.String())
	fmt.Println("----- END Challenge Message ----- ")

	authenticateData, _ := base64.StdEncoding.DecodeString(authenticateMessage)
	a, _ := messages.ParseAuthenticateMessage(authenticateData, 2)

	fmt.Println("----- Authenticate Message ----- ")
	fmt.Println(a.String())
	fmt.Println("----- END Authenticate Message ----- ")

	// Need the server challenge to be set
	server.SetServerChallenge(c.ServerChallenge)
	err = server.ProcessAuthenticateMessage(a)
	if err != nil {
		fmt.Printf("Could not process authenticate message: %s\n", err)
		return
	}
	fmt.Println("success")
}
