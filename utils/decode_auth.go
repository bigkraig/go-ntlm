package main

import (
	"encoding/base64"
	"fmt"
	"ntlm/messages"
)

func main() {
	var data string
	fmt.Println("Paste the base64 encoded Authenticate message:")
	fmt.Scanf("%s", &data)
	authenticateData, _ := base64.StdEncoding.DecodeString(data)
	a, _ := messages.ParseAuthenticateMessage(authenticateData, 2)
	fmt.Printf(a.String())
}
