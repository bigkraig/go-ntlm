# NTLM Implementation for Go


## Sample Usage as NTLM Client

```go
import "ntlm"
import "ntlm/messages"

session = ntlm.NewClientSession(ntlm.Version1, ntlm.ConnectionlessMode)
session.SetUserInfo("someuser","somepassword","somedomain")

negotiate := session.GenerateNegotiateMessage()

<send negotiate to server>

challenge, err := messages.ParseChallengeMessage(challengeBytes)
session.ProcessChallengeMessage(challenge)

authenticate := session.GenerateAuthenticateMessage()

<send authenticate message to server>
```

## Sample Usage as NTLM Server

```go
session = ntlm.NewServerSession(ntlm.Version1, ntlm.ConnectionlessMode)
session.SetUserInfo("someuser","somepassword","somedomain")

challenge := session.GenerateChallengeMessage()

<send challenge to client>

<receive authentication bytes>

auth, err := messages.ParseAuthentiateMessage(authenticateBytes)
session.ProcessAuthenticateMessage(auth)
```

## Generating a message MAC

Once a session is created you can generate the Mac for a message using:

```go
message := "this is some message to sign"
sequenceNumber := 100
signature, err := session.Mac([]byte(message), sequenceNumber)
```

## License
Copyright Thomson Reuters Global Resources 2013
Apache License
