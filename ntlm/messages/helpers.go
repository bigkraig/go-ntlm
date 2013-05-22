//Copyright 2013 Thomson Reuters Global Resources.  All Rights Reserved.  Proprietary and confidential information of TRGR.  Disclosure, use, or reproduction without written authorization of TRGR is prohibited.

package messages

import (
	"encoding/binary"
	"unicode/utf16"
)

// Convert a UTF16 string to UTF8 string for Go usage
func Utf16ToString(bytes []byte) string {
	var data []uint16

	// NOTE: This is definitely not the best way to do this, but when I tried using a buffer.Read I could not get it to work
	for offset := 0; offset < len(bytes); offset = offset + 2 {
		i := binary.LittleEndian.Uint16(bytes[offset : offset+2])
		data = append(data, i)
	}

	return string(utf16.Decode(data))
}

func StringToUtf16(value string) []byte {
	result := make([]byte, len(value)*2)
	stringBytes := []byte(value)
	for i := 0; i < len(value); i++ {
		result[i*2] = stringBytes[i]
	}
	return result
}

func Uint32ToBytes(v uint32) []byte {
	bytes := make([]byte, 4)
	bytes[0] = byte(v & 0xff)
	bytes[1] = byte((v >> 8) & 0xff)
	bytes[2] = byte((v >> 16) & 0xff)
	bytes[3] = byte((v >> 24) & 0xff)
	return bytes
}
