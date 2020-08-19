package odoh

import (
	"bytes"
	"testing"
)

func TestEncodeLengthPrefixedSlice(t *testing.T) {
	test_array := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := encodeLengthPrefixedSlice(test_array)
	expectation := []byte{0x00, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	if !bytes.Equal(result, expectation) {
		t.Fatalf("Result mismatch.")
	}
}

func TestDecodeLengthPrefixedSlice(t *testing.T) {
	test_array := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := encodeLengthPrefixedSlice(test_array)
	decoded_result, length, err := decodeLengthPrefixedSlice(result)
	if err != nil {
		t.Fatalf("Raised an error. Decoding error.")
	}
	if !bytes.Equal(test_array, decoded_result) {
		t.Fatalf("Decoding result mismatch.")
	}
	if len(test_array)+2 != length {
		t.Fatalf("Incorrect length in the encoded message.")
	}
}
