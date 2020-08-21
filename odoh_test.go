// The MIT License
//
// Copyright (c) 2019 Apple, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package odoh

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/cisco/go-hpke"
	"io"
	"testing"
)

func TestQueryBodyMarshal(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x04}
	message := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	queryBody := ObliviousDNSQuery{
		ResponseKey: key,
		DnsMessage:  message,
	}

	encoded := queryBody.Marshal()
	decoded, err := UnmarshalQueryBody(encoded)
	if err != nil {
		t.Fatalf("Encode/decode failed")
	}
	if !bytes.Equal(decoded.ResponseKey, key) {
		t.Fatalf("Key mismatch")
	}
	if !bytes.Equal(decoded.DnsMessage, message) {
		t.Fatalf("Key mismatch")
	}
}

func TestDNSMessageMarshal(t *testing.T) {
	keyID := []byte{0x00, 0x01, 0x02, 0x04}
	encryptedMessage := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	message := ObliviousDNSMessage{
		MessageType:      0x01,
		KeyID:            keyID,
		EncryptedMessage: encryptedMessage,
	}

	encoded := message.Marshal()
	decoded, err := UnmarshalDNSMessage(encoded)
	if err != nil {
		t.Fatalf("Encode/decode failed")
	}
	if decoded.MessageType != 0x01 {
		t.Fatalf("MessageType mismatch")
	}
	if !bytes.Equal(decoded.KeyID, keyID) {
		t.Fatalf("KeyID mismatch")
	}
	if !bytes.Equal(decoded.EncryptedMessage, encryptedMessage) {
		t.Fatalf("EncryptedMessage mismatch")
	}
}

func TestQueryEncryption(t *testing.T) {
	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	skR, pkR, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	targetKey := ObliviousDNSPublicKey{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pkR),
	}

	odohKeyPair := ObliviousDNSKeyPair{targetKey, skR}
	symmetricKey := make([]byte, suite.AEAD.KeySize())
	rand.Read(symmetricKey)

	dnsMessage := []byte{0x01, 0x02}

	message := ObliviousDNSQuery{
		ResponseKey: symmetricKey,
		DnsMessage:  dnsMessage,
	}

	encryptedMessage, err := targetKey.EncryptQuery(message)
	if err != nil {
		t.Fatalf("EncryptQuery failed: %s", err)
	}

	result, err := odohKeyPair.DecryptQuery(encryptedMessage)
	if err != nil {
		t.Fatalf("DecryptQuery failed: %s", err)
	}

	if !bytes.Equal(result.ResponseKey, symmetricKey) {
		t.Fatalf("Incorrect key returned")
	}
	if !bytes.Equal(result.DnsMessage, dnsMessage) {
		t.Fatalf("Incorrect DnsMessage returned")
	}
}

func TestKeyID(t *testing.T) {
	expectedKeyId := "002050106dbb316e7bf98bc862fd71e131d28cd871a11af84b19f323e465f32f1006"
	expectedKeyIdBytes, err := hex.DecodeString(expectedKeyId)
	if err != nil {
		t.Fatal("Failed to decode AAD")
	}

	publicKey := "85023a65b2c505cd2e92e2c427ef69df8aa8d0f18081a8090b159aafa6001413"
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		t.Fatal("Failed to decode public key")
	}

	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128
	odohKey := ObliviousDNSPublicKey{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: publicKeyBytes,
	}

	keyId := odohKey.KeyID()
	if !bytes.Equal(keyId, expectedKeyIdBytes) {
		t.Fatalf("Incorrect keyId returned")
	}
}

func Test_Sender_ODOHQueryEncryption(t *testing.T) {
	kemID := hpke.DHKEM_P256      // 0x0010
	kdfID := hpke.KDF_HKDF_SHA256 // 0x0001
	aeadID := hpke.AEAD_AESGCM128 // 0x0001

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	responseKey := make([]byte, suite.AEAD.KeySize())
	if _, err := io.ReadFull(rand.Reader, responseKey); err != nil {
		t.Fatalf("Failed generating random key: %s", err)
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)

	skR, pkR, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	targetKey := ObliviousDNSPublicKey{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pkR),
	}

	odohKeyPair := ObliviousDNSKeyPair{targetKey, skR}
	symmetricKey := make([]byte, suite.AEAD.KeySize())
	rand.Read(symmetricKey)

	dnsMessage := []byte{0x01, 0x02, 0x03}

	message := ObliviousDNSQuery{
		ResponseKey: symmetricKey,
		DnsMessage:  dnsMessage,
	}

	encryptedMessage, err := targetKey.EncryptQuery(message)
	fmt.Printf("%v\n", encryptedMessage)

	if err != nil {
		t.Fatalf("Failed to encrypt the message using the public key.")
	}

	encryptedMessageMarshal := encryptedMessage.Marshal()
	fmt.Printf("%v\n", encryptedMessageMarshal)

	dnsQuery, err := odohKeyPair.DecryptQuery(encryptedMessage)
	fmt.Printf("%v\n", dnsQuery)
}

func TestResponseEncryption(t *testing.T) {
	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	responseKey := make([]byte, suite.AEAD.KeySize())
	if _, err := io.ReadFull(rand.Reader, responseKey); err != nil {
		t.Fatalf("Failed generating random key: %s", err)
	}

	aad := []byte("ODOH")
	responseData := []byte("fake response")

	query := ObliviousDNSQuery{
		ResponseKey: responseKey,
		DnsMessage:  nil,
	}

	encryptedResponse, err := query.EncryptResponse(suite, aad, responseData)
	if err != nil {
		t.Fatalf("Failed EncryptResponse: %s", err)
	}

	response := ObliviousDNSResponse{
		ResponseKey: responseKey,
	}

	decryptedResponse, err := response.DecryptResponse(suite, aad, encryptedResponse)
	if err != nil {
		t.Fatalf("Failed EncryptResponse: %s", err)
	}

	if !bytes.Equal(decryptedResponse, responseData) {
		t.Fatalf("Incorrect message returned")
	}
}

func TestEncoding(t *testing.T) {
	emptySlice := make([]byte, 0)
	if !bytes.Equal([]byte{0x00, 0x00}, encodeLengthPrefixedSlice(emptySlice)) {
		t.Fatalf("encodeLengthPrefixedSlice for empty slice failed")
	}
}

func TestOdohPublicKeyMarshalUnmarshal(t *testing.T) {
	kemID := hpke.DHKEM_P256      // 0x0010
	kdfID := hpke.KDF_HKDF_SHA256 // 0x0001
	aeadID := hpke.AEAD_AESGCM128 // 0x0001

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	responseKey := make([]byte, suite.AEAD.KeySize())
	if _, err := io.ReadFull(rand.Reader, responseKey); err != nil {
		t.Fatalf("Failed generating random key: %s", err)
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)

	_, pkR, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	targetKey := ObliviousDNSPublicKey{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pkR),
	}

	serializedPublicKey := targetKey.Marshal()

	fmt.Printf("%v %v\n", len(serializedPublicKey), serializedPublicKey)

	deserializedPublicKey := UnMarshalObliviousDNSPublicKey(serializedPublicKey)

	if !bytes.Equal(deserializedPublicKey.PublicKeyBytes, targetKey.PublicKeyBytes) {
		t.Fatalf("The deserialized and serialized bytes do not match.")
	}

	if deserializedPublicKey.KemID != targetKey.KemID {
		t.Fatalf("The KEM IDs do not match.")
	}

	if deserializedPublicKey.KdfID != targetKey.KdfID {
		t.Fatalf("The KDF IDs do not match.")
	}

	if deserializedPublicKey.AeadID != targetKey.AeadID {
		t.Fatalf("The AEAD IDs do not match.")
	}
}

func TestFixedOdohKeyPairCreation(t *testing.T) {
	const (
		kemID  = hpke.DHKEM_X25519
		kdfID  = hpke.KDF_HKDF_SHA256
		aeadID = hpke.AEAD_AESGCM128
	)
	// Fixed 16 byte seed
	seedHex := "f7c664a7959b2aa02ffa7abb0d2022ab"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Printf("Unable to decode seed to bytes")
	}
	keyPair, err := DeriveFixedKeyPairFromSeed(kemID, kdfID, aeadID, seed)
	if err != nil {
		fmt.Printf("Unable to derive a ObliviousDNSKeyPair")
	}
	for i := 0; i < 10; i++ {
		keyPairDerived, err := DeriveFixedKeyPairFromSeed(kemID, kdfID, aeadID, seed)
		if err != nil {
			t.Fatalf("Unable to derive a ObliviousDNSKeyPair")
		}
		if !bytes.Equal(keyPairDerived.PublicKey.Marshal(), keyPair.PublicKey.Marshal()) {
			t.Fatalf("Public Key Derived does not match")
		}
	}
}

func TestSealQueryAndOpenAnswer(t *testing.T) {
	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)

	kp, err := CreateKeyPair(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("Unable to create a Key Pair")
	}

	responseKey := make([]byte, 16)
	dnsQueryData := make([]byte, 40)
	_, err = rand.Read(responseKey)
	_, err = rand.Read(dnsQueryData)

	encryptedData, err := SealQuery(dnsQueryData, responseKey, kp.PublicKey)

	mockAnswerData := make([]byte, 100)
	_, err = rand.Read(mockAnswerData)

	receivedEncryptedQuery, err := UnmarshalDNSMessage(encryptedData)

	queryRequested, err := kp.DecryptQuery(*receivedEncryptedQuery)
	responseKeyId := []byte{0x00, 0x00}
	aad := append([]byte{byte(ResponseType)}, responseKeyId...) // message_type = 0x02, with an empty keyID
	encryptedAnswer, err := queryRequested.EncryptResponse(suite, aad, mockAnswerData)
	encryptedResponseMessage := CreateObliviousDNSMessage(ResponseType, []byte{}, encryptedAnswer)

	response, err := OpenAnswer(encryptedResponseMessage, responseKey, suite)

	if !bytes.Equal(response, mockAnswerData) {
		t.Fatalf("Decryption of the result doesnot match encrypted value")
	}
}