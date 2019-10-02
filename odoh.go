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
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/bifurcation/hpke"
	"log"
)

type ObliviousDNSPublicKey struct {
	kemID          hpke.KEMID
	kdfID          hpke.KDFID
	aeadID         hpke.AEADID
	publicKeyBytes []byte
}

func (k ObliviousDNSPublicKey) KeyID() []byte {
	h := sha256.New()

	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], uint16(k.kemID))
	binary.BigEndian.PutUint16(identifiers[2:], uint16(k.kdfID))
	binary.BigEndian.PutUint16(identifiers[4:], uint16(k.aeadID))
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.publicKeyBytes)))
	message := append(identifiers, k.publicKeyBytes...)

	h.Write(message)
	keyIdHash := h.Sum(nil)

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, uint16(len(keyIdHash)))
	return append(result, keyIdHash...)
}

func (k ObliviousDNSPublicKey) CipherSuite() (hpke.CipherSuite, error) {
	return hpke.AssembleCipherSuite(k.kemID, k.kdfID, k.aeadID)
}

type ObliviousDNSPrivateKey struct {
	ObliviousDNSPublicKey
	secretKey hpke.KEMPrivateKey
}

func (k ObliviousDNSPrivateKey) CipherSuite() (hpke.CipherSuite, error) {
	return hpke.AssembleCipherSuite(k.kemID, k.kdfID, k.aeadID)
}

func CreatePrivateKey(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) (ObliviousDNSPrivateKey, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDNSPrivateKey{}, err
	}

	sk, pk, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		return ObliviousDNSPrivateKey{}, err
	}

	publicKey := ObliviousDNSPublicKey{
		kemID:          kemID,
		kdfID:          kdfID,
		aeadID:         aeadID,
		publicKeyBytes: suite.KEM.Marshal(pk),
	}

	return ObliviousDNSPrivateKey{publicKey, sk}, nil
}

func (targetKey ObliviousDNSPublicKey) EncryptQuery(query ObliviousDNSQuery) (ObliviousDNSMessage, error) {
	suite, err := hpke.AssembleCipherSuite(targetKey.kemID, targetKey.kdfID, targetKey.aeadID)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	pkR, err := suite.KEM.Unmarshal(targetKey.publicKeyBytes)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	enc, ctxI, err := hpke.SetupBaseI(suite, rand.Reader, pkR, []byte("odns-query"))
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	encodedMessage := query.Marshal()
	aad := append([]byte{0x01}, targetKey.KeyID()...)
	ct := ctxI.Seal(aad, encodedMessage)

	return ObliviousDNSMessage{
		messageType:      0x01,
		keyID:            targetKey.KeyID(),
		encryptedMessage: append(enc, ct...),
	}, nil
}

func (privateKey ObliviousDNSPrivateKey) DecryptQuery(message ObliviousDNSMessage) (*ObliviousDNSQuery, error) {
	suite, err := hpke.AssembleCipherSuite(privateKey.kemID, privateKey.kdfID, privateKey.aeadID)
	if err != nil {
		return nil, err
	}

	log.Printf("publicKey = %x\n", privateKey.publicKeyBytes)

	enc := message.encryptedMessage[0:32]
	ct := message.encryptedMessage[32:]
	log.Printf("enc = %x\n", enc)
	log.Printf("ct = %x\n", ct)

	ctxR, err := hpke.SetupBaseR(suite, privateKey.secretKey, enc, []byte("odns-query"))
	if err != nil {
		return nil, err
	}

	aad := append([]byte{0x01}, privateKey.KeyID()...)
	log.Printf("aad = %x\n", aad)

	dnsMessage, err := ctxR.Open(aad, ct)
	if err != nil {
		return nil, err
	}

	return UnmarshalQueryBody(dnsMessage)
}
