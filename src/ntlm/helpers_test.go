package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUTf16ToString(t *testing.T) {
	expected, _ := hex.DecodeString("5500730065007200")
	result := utf16FromString("User")
	if !bytes.Equal(expected, result) {
		t.Errorf("UTF16ToString failed got %s expected %s", hex.EncodeToString(result), "5500730065007200")
	}
}
