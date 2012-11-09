package ntlm

import (
	"bytes"
	"encoding/hex"
	"ntlm/messages"
	"strings"
	"testing"
)

func checkV2Value(t *testing.T, name string, value []byte, expected string, err error) {
	if err != nil {
		t.Errorf("NTLMv2 %s received error: %s", name, err)
	} else {
		expectedBytes, _ := hex.DecodeString(expected)
		if !bytes.Equal(expectedBytes, value) {
			t.Errorf("NTLMv2 %s is not correct got %s expected %s", name, hex.EncodeToString(value), expected)
		}
	}
}

func TestNTOWFv2(t *testing.T) {
	result := ntowfv2("User", "Password", "Domain")
	// Sample value from 4.2.4.1.1 in MS-NLMP
	expected, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(result, expected) {
		t.Errorf("NTOWFv2 is not correct got %s expected %s", hex.EncodeToString(result), "0c868a403bfd7a93a3001ef22ef02e3f")
	}
}

func TestNTLMv2(t *testing.T) {
	flags := uint32(0)
	flags = messages.NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = messages.NTLMSSP_TARGET_TYPE_SERVER.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = messages.NTLM_NEGOTIATE_OEM.Set(flags)
	flags = messages.NTLMSSP_NEGOTIATE_UNICODE.Set(flags)

	//	n := new(V2Session)
	//	n.SetUserInfo("User","Password","Domain")
	//	n.negotiateFlags = flags
	//	n.responseKeyNT, _ = hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	//	n.responseKeyLM = n.responseKeyNT
	//	n.clientChallenge, _ = hex.DecodeString("aaaaaaaaaaaaaaaa")
	//	n.serverChallenge, _ = hex.DecodeString("0123456789abcdef")

	// Encrypted Random Session key
	//c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e

	// Challenge message
	client := new(V2ClientSession)
	client.SetUserInfo("User", "Password", "Domain")

	challengeMessageBytes, _ := hex.DecodeString("4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	challengeMessage, err := messages.ParseChallengeMessage(challengeMessageBytes)
	if err == nil {
		challengeMessage.String()
	} else {
		t.Errorf("Could not parse challenge message: %s", err)
	}

	err = client.ProcessChallengeMessage(challengeMessage)
	if err != nil {
		t.Errorf("Could not process challenge message: %s", err)
	}

	server := new(V2ServerSession)
	server.SetUserInfo("User", "Password", "Domain")
	server.serverChallenge = challengeMessage.ServerChallenge

	// Authenticate message
	r := strings.NewReplacer("\n", "", "\t", "", " ", "")
	authenticateMessageBytes, _ := hex.DecodeString(r.Replace(`
		4e544c4d535350000300000018001800
		6c00000054005400840000000c000c00
		48000000080008005400000010001000
		5c00000010001000d8000000358288e2
		0501280a0000000f44006f006d006100
		69006e00550073006500720043004f00
		4d005000550054004500520086c35097
		ac9cec102554764a57cccc19aaaaaaaa
		aaaaaaaa68cd0ab851e51c96aabc927b
		ebef6a1c010100000000000000000000
		00000000aaaaaaaaaaaaaaaa00000000
		02000c0044006f006d00610069006e00
		01000c00530065007200760065007200
		0000000000000000c5dad2544fc97990
		94ce1ce90bc9d03e`))

	authenticateMessage, err := messages.ParseAuthenticateMessage(authenticateMessageBytes, 2)
	if err == nil {
		authenticateMessage.String()
	} else {
		t.Errorf("Could not parse authenticate message: %s", err)
	}

	err = server.ProcessAuthenticateMessage(authenticateMessage)
	if err != nil {
		t.Errorf("Could not process authenticate message: %s", err)
	}

	checkV2Value(t, "SessionBaseKey", server.sessionBaseKey, "8de40ccadbc14a82f15cb0ad0de95ca3", nil)
	checkV2Value(t, "NTChallengeResponse", server.ntChallengeResponse[0:16], "68cd0ab851e51c96aabc927bebef6a1c", nil)
	checkV2Value(t, "LMChallengeResponse", server.lmChallengeResponse, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa", nil)

	checkV2Value(t, "client seal key", server.clientSealingKey, "59f600973cc4960a25480a7c196e4c58", nil)
	checkV2Value(t, "client seal key", server.clientSigningKey, "4788dc861b4782f35d43fd98fe1a2d39", nil)
}
