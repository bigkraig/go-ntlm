//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import "bytes"

type NegotiateMessage struct {
	// All bytes of the message
	Bytes []byte

	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

func (n *NegotiateMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Negotiate NTLM Message")
	// buffer.WriteString(fmt.Sprintf("\nPayload Offset: %d Length: %d", c.getLowestPayloadOffset(), len(c.Payload)))
	// buffer.WriteString(fmt.Sprintf("\nTargetName: %s", c.TargetName.String()))
	// buffer.WriteString(fmt.Sprintf("\nServerChallenge: %s", hex.EncodeToString(c.ServerChallenge)))
	// if c.Version != nil {
	// 	buffer.WriteString(fmt.Sprintf("\nVersion: %s\n", c.Version.String()))
	// }
	// buffer.WriteString("\nTargetInfo")
	// buffer.WriteString(c.TargetInfo.String())
	// buffer.WriteString(fmt.Sprintf("\nFlags %d\n", c.NegotiateFlags))
	// buffer.WriteString(FlagsToString(c.NegotiateFlags))

	return buffer.String()
}
