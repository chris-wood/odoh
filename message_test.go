package odoh

import (
	"bytes"
	"testing"
)

func TestObliviousDNSQuery_Marshal(t *testing.T) {
	responseKey := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	dnsMessage := []byte{0x06, 0x07, 0x08, 0x09}
	query := ObliviousDNSQuery{
		ResponseKey: responseKey,
		DnsMessage:  dnsMessage,
	}
	marshaled_query := query.Marshal()
	expected_bytes := []byte{0x00, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x04, 0x06, 0x07, 0x08, 0x09}
	if !bytes.Equal(marshaled_query, expected_bytes) {
		t.Fatalf("Marshalling mismatch in the encoding.")
	}
}

func TestObliviousDNSMessage_Marshal(t *testing.T) {
	messageType := QueryType
	keyId := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	encryptedMessage := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	odnsMessage := ObliviousDNSMessage{
		MessageType:      messageType,
		KeyID:            keyId,
		EncryptedMessage: encryptedMessage,
	}

	serialized_odns_message := odnsMessage.Marshal()
	expectation := []byte{0x01,
		0x00, 0x05,
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x00, 0x0B,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	if !bytes.Equal(serialized_odns_message, expectation) {
		t.Fatalf("Failed to serialize correctly.")
	}
}

func TestObliviousDNSMessage_Unmarshal(t *testing.T) {
	messageType := QueryType
	keyId := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	encryptedMessage := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	odnsMessage := ObliviousDNSMessage{
		MessageType:      messageType,
		KeyID:            keyId,
		EncryptedMessage: encryptedMessage,
	}

	expectation := []byte{0x01,
		0x00, 0x05,
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x00, 0x0B,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	unmarshaled_odnsMessage, err := UnmarshalDNSMessage(expectation)

	if err != nil {
		t.Fatalf("Failed to unmarshal ObliviousDNSMessage")
	}

	if !(unmarshaled_odnsMessage.MessageType == odnsMessage.MessageType) {
		t.Fatalf("Message type mismatch after unmarshaling")
	}

	if !bytes.Equal(unmarshaled_odnsMessage.KeyID, odnsMessage.KeyID) {
		t.Fatalf("Failed to unmarshal the KeyID correctly.")
	}

	if !bytes.Equal(unmarshaled_odnsMessage.EncryptedMessage, odnsMessage.EncryptedMessage) {
		t.Fatalf("Failed to unmarshal the Encrypted Message Correctly.")
	}
}
