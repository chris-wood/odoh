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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/cisco/go-hpke"
)

type ObliviousMessageType uint8

const (
	QueryType    ObliviousMessageType = 0x01
	ResponseType ObliviousMessageType = 0x02
)

const ResponseSeedLength uint16 = 32

type ObliviousDNSQuery struct {
	DnsMessage   []byte
	ResponseSeed [ResponseSeedLength]byte
	Padding      []byte
}

func (m ObliviousDNSQuery) Marshal() []byte {
	result := encodeLengthPrefixedSlice(m.DnsMessage)
	result = append(result, m.ResponseSeed[:]...)
	result = append(result, encodeLengthPrefixedSlice(m.Padding)...)
	return result
}

func UnmarshalQueryBody(data []byte) (*ObliviousDNSQuery, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("Invalid data length: %d", len(data))
	}

	message, offset, err := decodeLengthPrefixedSlice(data)
	if err != nil {
		return nil, err
	}
	
	if offset + int(ResponseSeedLength) > len(data) {
		return nil, fmt.Errorf("Invalid response seed length")
	}
	var seed [ResponseSeedLength]byte
	copy(seed[:], data[offset : offset + int(ResponseSeedLength)])

	padding, offset, err := decodeLengthPrefixedSlice(data[offset + int(ResponseSeedLength):])
	if err != nil {
		return nil, err
	}

	return &ObliviousDNSQuery{
		DnsMessage:   message,
		ResponseSeed: seed,
		Padding: padding,
	}, nil
}

func (m ObliviousDNSQuery) Message() []byte {
	return m.DnsMessage
}

func (m ObliviousDNSQuery) EncryptResponse(suite hpke.CipherSuite, aad, response []byte) ([]byte, error) {
	// TODO(caw): we need to support other ciphersuites, so dispatch on `suite`
	key, nonce := DeriveKeyNonce(suite, m)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, response, aad)

	return ciphertext, nil
}

type ObliviousDNSResponse struct {
	ResponseKey []byte
}

func (r ObliviousDNSResponse) DecryptResponse(suite hpke.CipherSuite, aad, response []byte, query ObliviousDNSQuery) ([]byte, error) {
	// TODO(caw): we need to support other ciphersuites, so dispatch on `suite`
	key, nonce := DeriveKeyNonce(suite, query)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, response, aad)
	return plaintext, err
}

type ObliviousDNSResponseBody struct {
	DnsMessage []byte 
	Padding    []byte
}

func (m ObliviousDNSResponseBody) Marshal() []byte {
	result := encodeLengthPrefixedSlice(m.DnsMessage)
	result = append(result, encodeLengthPrefixedSlice(m.Padding)...)
	return result
}

func UnmarshalDNSResponse(data []byte) (*ObliviousDNSResponseBody, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("Invalid data length: %d", len(data))
	}

	message, offset, err := decodeLengthPrefixedSlice(data)
	if err != nil {
		return nil, err
	}

	padding, offset, err := decodeLengthPrefixedSlice(data[offset:])
	if err != nil {
		return nil, err
	}

	return &ObliviousDNSResponseBody {
		DnsMessage: message,
		Padding: padding,
	}, nil
}

func CreateObliviousDNSResponseBody(msg []byte, padding []byte) *ObliviousDNSResponseBody {
	return &ObliviousDNSResponseBody{
		DnsMessage: msg,
		Padding:    padding,
	}
}

type ObliviousDNSMessage struct {
	MessageType      ObliviousMessageType
	KeyID            []byte
	EncryptedMessage []byte
}

func (m ObliviousDNSMessage) Type() ObliviousMessageType {
	return m.MessageType
}

func CreateObliviousDNSMessage(messageType ObliviousMessageType, keyID []byte, encryptedMessage []byte) *ObliviousDNSMessage {
	return &ObliviousDNSMessage{
		MessageType:      messageType,
		KeyID:            keyID,
		EncryptedMessage: encryptedMessage,
	}
}

func (m ObliviousDNSMessage) Marshal() []byte {
	encodedKey := encodeLengthPrefixedSlice(m.KeyID)
	encodedMessage := encodeLengthPrefixedSlice(m.EncryptedMessage)

	result := append([]byte{uint8(m.MessageType)}, encodedKey...)
	result = append(result, encodedMessage...)

	return result
}

func UnmarshalDNSMessage(data []byte) (*ObliviousDNSMessage, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("Invalid data length: %d", len(data))
	}

	messageType := data[0]
	keyID, offset, err := decodeLengthPrefixedSlice(data[1:])
	if err != nil {
		return nil, err
	}
	encryptedMessage, offset, err := decodeLengthPrefixedSlice(data[1+offset:])
	if err != nil {
		return nil, err
	}

	return &ObliviousDNSMessage{
		MessageType:      ObliviousMessageType(messageType),
		KeyID:            keyID,
		EncryptedMessage: encryptedMessage,
	}, nil
}
