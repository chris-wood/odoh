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
	"encoding/json"
	"fmt"
	"github.com/cisco/go-hpke"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

const (
	outputTestVectorEnvironmentKey = "ODOH_TEST_VECTORS_OUT"
	inputTestVectorEnvironmentKey  = "ODOH_TEST_VECTORS_IN"
	numTransactions                = 2
	baseQuerySize                  = 32
)

func TestQueryBodyMarshal(t *testing.T) {
	message := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	queryBody := CreateObliviousDNSQuery(message, 0)

	encoded := queryBody.Marshal()
	decoded, err := UnmarshalQueryBody(encoded)
	if err != nil {
		t.Fatalf("Encode/decode failed")
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

	targetKey := ObliviousDoHConfigContents{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pkR),
	}

	targetConfig := ObliviousDoHConfig{
		Contents: targetKey,
	}

	odohKeyPair := ObliviousDoHKeyPair{targetConfig, skR, ikm}

	dnsMessage := []byte{0x01, 0x02}

	message := CreateObliviousDNSQuery(dnsMessage, 0)

	encryptedMessage, _, err := targetKey.EncryptQuery(message)
	if err != nil {
		t.Fatalf("EncryptQuery failed: %s", err)
	}

	result, _, err := odohKeyPair.DecryptQuery(encryptedMessage)
	if err != nil {
		t.Fatalf("DecryptQuery failed: %s", err)
	}

	if !bytes.Equal(result.DnsMessage, dnsMessage) {
		t.Fatalf("Incorrect DnsMessage returned")
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

	targetKey := ObliviousDoHConfigContents{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pkR),
	}

	targetConfig := ObliviousDoHConfig{
		Contents: targetKey,
	}

	odohKeyPair := ObliviousDoHKeyPair{targetConfig, skR, ikm}
	symmetricKey := make([]byte, suite.AEAD.KeySize())
	rand.Read(symmetricKey)

	dnsMessage := []byte{0x01, 0x02, 0x03}
	message := CreateObliviousDNSQuery(dnsMessage, 0)

	encryptedMessage, _, err := targetKey.EncryptQuery(message)
	if err != nil {
		t.Fatalf("Failed to encrypt the message using the public key.")
	}

	dnsQuery, _, err := odohKeyPair.DecryptQuery(encryptedMessage)
	if err != nil {
		t.Fatalf("Failed to decrypt message with error: %s", err)
	}

	if !bytes.Equal(dnsQuery.DnsMessage, dnsMessage) {
		t.Fatalf("Incorrect dnsMessage returned")
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

	targetKey := ObliviousDoHConfigContents{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pkR),
	}

	serializedPublicKey := targetKey.Marshal()
	deserializedPublicKey := UnmarshalObliviousDoHConfigContents(serializedPublicKey)

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
		t.Fatalf("Unable to decode seed to bytes")
	}
	keyPair, err := DeriveFixedKeyPairFromSeed(kemID, kdfID, aeadID, seed)
	if err != nil {
		t.Fatalf("Unable to derive a ObliviousDoHKeyPair")
	}
	for i := 0; i < 10; i++ {
		keyPairDerived, err := DeriveFixedKeyPairFromSeed(kemID, kdfID, aeadID, seed)
		if err != nil {
			t.Fatalf("Unable to derive a ObliviousDoHKeyPair")
		}
		if !bytes.Equal(keyPairDerived.Config.Contents.Marshal(), keyPair.Config.Contents.Marshal()) {
			t.Fatalf("Public Key Derived does not match")
		}
	}
}

func TestSealQueryAndOpenAnswer(t *testing.T) {
	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128

	kp, err := CreateKeyPair(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("Unable to create a Key Pair")
	}

	dnsQueryData := make([]byte, 40)
	_, err = rand.Read(dnsQueryData)

	encryptedData, queryContext, err := SealQuery(dnsQueryData, kp.Config.Contents)

	mockAnswerData := make([]byte, 100)
	_, err = rand.Read(mockAnswerData)

	_, responseContext, err := kp.DecryptQuery(encryptedData)

	mockResponse := CreateObliviousDNSResponse(mockAnswerData, 0)
	encryptedAnswer, err := responseContext.EncryptResponse(mockResponse)

	response, err := queryContext.OpenAnswer(encryptedAnswer)

	if !bytes.Equal(response, mockAnswerData) {
		t.Fatalf("Decryption of the result does not match encrypted value")
	}
}

///////
// Assertions
func assert(t *testing.T, msg string, test bool) {
	if !test {
		t.Fatalf("%s", msg)
	}
}

func assertBytesEqual(t *testing.T, msg string, lhs, rhs []byte) {
	realMsg := fmt.Sprintf("%s: [%x] != [%x]", msg, lhs, rhs)
	assert(t, realMsg, bytes.Equal(lhs, rhs))
}

func assertNotError(t *testing.T, msg string, err error) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	assert(t, realMsg, err == nil)
}

func fatalOnError(t *testing.T, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatalf(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func mustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func mustDeserializePub(t *testing.T, suite hpke.CipherSuite, h string, required bool) hpke.KEMPublicKey {
	pkm := mustUnhex(t, h)
	pk, err := suite.KEM.Deserialize(pkm)
	if required {
		fatalOnError(t, err, "Deserialize failed")
	}
	return pk
}

func mustSerializePub(suite hpke.CipherSuite, pub hpke.KEMPublicKey) string {
	return mustHex(suite.KEM.Serialize(pub))
}

///////
// Query/Response transaction test vector structure
type transactionTestVector struct {
	query             []byte
	response          []byte
	obliviousQuery    ObliviousDNSMessage
	obliviousResponse ObliviousDNSMessage
}

func (etv transactionTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"query":             mustHex(etv.query),
		"response":          mustHex(etv.response),
		"obliviousQuery":    mustHex(etv.obliviousQuery.Marshal()),
		"obliviousResponse": mustHex(etv.obliviousResponse.Marshal()),
	})
}

func (etv *transactionTestVector) UnmarshalJSON(data []byte) error {
	raw := map[string]string{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.query = mustUnhex(nil, raw["query"])
	etv.response = mustUnhex(nil, raw["response"])

	obliviousQueryBytes := mustUnhex(nil, raw["obliviousQuery"])
	obliviousResponseBytes := mustUnhex(nil, raw["obliviousResponse"])

	etv.obliviousQuery, err = UnmarshalDNSMessage(obliviousQueryBytes)
	if err != nil {
		return err
	}
	etv.obliviousResponse, err = UnmarshalDNSMessage(obliviousResponseBytes)
	if err != nil {
		return err
	}

	return nil
}

type rawTestVector struct {
	KemID         int    `json:"kem_id"`
	KdfID         int    `json:"kdf_id"`
	AeadID        int    `json:"aead_id"`
	Config        string `json:"odohconfig"`
	PublicKeySeed string `json:"public_key_seed"`
	KeyId         string `json:"key_id"`

	Transactions []transactionTestVector `json:"transactions"`
}

type testVector struct {
	t               *testing.T
	kem_id          hpke.KEMID
	kdf_id          hpke.KDFID
	aead_id         hpke.AEADID
	odoh_config     []byte
	public_key_seed []byte
	key_id          []byte

	transactions []transactionTestVector
}

func (tv testVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTestVector{
		KemID:         int(tv.kem_id),
		KdfID:         int(tv.kdf_id),
		AeadID:        int(tv.aead_id),
		Config:        mustHex(tv.odoh_config),
		PublicKeySeed: mustHex(tv.public_key_seed),
		KeyId:         mustHex(tv.key_id),
		Transactions:  tv.transactions,
	})
}

func (tv *testVector) UnmarshalJSON(data []byte) error {
	raw := rawTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tv.kem_id = hpke.KEMID(raw.KemID)
	tv.kdf_id = hpke.KDFID(raw.KdfID)
	tv.aead_id = hpke.AEADID(raw.AeadID)
	tv.public_key_seed = mustUnhex(tv.t, raw.PublicKeySeed)
	tv.odoh_config = mustUnhex(tv.t, raw.Config)
	tv.key_id = mustUnhex(tv.t, raw.KeyId)

	tv.transactions = raw.Transactions
	return nil
}

type testVectorArray struct {
	t       *testing.T
	vectors []testVector
}

func (tva testVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *testVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func generateRandomData(n int) []byte {
	data := make([]byte, n)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	return data
}

func generateTransaction(t *testing.T, kp ObliviousDoHKeyPair, querySize int) transactionTestVector {
	mockQuery := generateRandomData(querySize)
	mockAnswer := append(mockQuery, mockQuery...) // answer = query || query

	// Run the query/response transaction
	obliviousQuery, queryContext, err := SealQuery(mockQuery, kp.Config.Contents)
	_, responseContext, err := kp.DecryptQuery(obliviousQuery)

	mockResponse := CreateObliviousDNSResponse(mockAnswer, 0)
	obliviousResponse, err := responseContext.EncryptResponse(mockResponse)
	response, err := queryContext.OpenAnswer(obliviousResponse)

	if err != nil || !bytes.Equal(response, mockAnswer) {
		t.Fatalf("Decryption of the result does not match encrypted value")
	}

	return transactionTestVector{
		query:             mockQuery,
		obliviousQuery:    obliviousQuery,
		response:          mockAnswer,
		obliviousResponse: obliviousResponse,
	}
}

func generateTestVector(t *testing.T, kem_id hpke.KEMID, kdf_id hpke.KDFID, aead_id hpke.AEADID) testVector {
	kp, err := CreateKeyPair(kem_id, kdf_id, aead_id)
	if err != nil {
		t.Fatalf("Unable to create a Key Pair")
	}

	transactions := make([]transactionTestVector, numTransactions)
	for i := 0; i < numTransactions; i++ {
		transactions[i] = generateTransaction(t, kp, (i+1)*baseQuerySize)
	}

	vector := testVector{
		t:               t,
		kem_id:          kem_id,
		kdf_id:          kdf_id,
		aead_id:         aead_id,
		odoh_config:     kp.Config.Marshal(),
		public_key_seed: kp.seed,
		key_id:          kp.Config.Contents.KeyID(),
		transactions:    transactions,
	}

	return vector
}

func verifyTestVector(t *testing.T, tv testVector) {
	config, err := UnmarshalObliviousDoHConfig(tv.odoh_config)
	assertNotError(t, "UnmarshalObliviousDoHConfigContents failed", err)

	kp, err := DeriveFixedKeyPairFromSeed(config.Contents.KemID, config.Contents.KdfID, config.Contents.AeadID, tv.public_key_seed)
	assertNotError(t, "DeriveFixedKeyPairFromSeed failed", err)

	expectedKeyId := kp.Config.Contents.KeyID()
	assertBytesEqual(t, "KeyID mismatch", expectedKeyId, tv.key_id)

	for _, transaction := range tv.transactions {
		query, responseContext, err := kp.DecryptQuery(transaction.obliviousQuery)
		assertNotError(t, "Query decryption failed", err)
		assertBytesEqual(t, "Query decryption mismatch", query.DnsMessage, transaction.query)

		testResponse := CreateObliviousDNSResponse(transaction.response, 0)
		obliviousResponse, err := responseContext.EncryptResponse(testResponse)
		assertNotError(t, "Response encryption failed", err)
		assertBytesEqual(t, "Response encryption mismatch", obliviousResponse.Marshal(), transaction.obliviousResponse.Marshal())

		// Extract decryption context, since we don't control the client's ephemeral key
		queryContext := QueryContext{
			odohSecret: responseContext.odohSecret,
			query:      query.Marshal(),
			suite:      responseContext.suite,
		}
		response, err := queryContext.OpenAnswer(obliviousResponse)
		assertNotError(t, "Response decryption failed", err)
		assertBytesEqual(t, "Final response encryption mismatch", response, transaction.response)
	}
}

func vectorTest(vector testVector) func(t *testing.T) {
	return func(t *testing.T) {
		verifyTestVector(t, vector)
	}
}

func verifyTestVectors(t *testing.T, vectorString []byte, subtest bool) {
	vectors := testVectorArray{t: t}
	err := json.Unmarshal(vectorString, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, tv := range vectors.vectors {
		test := vectorTest(tv)
		if !subtest {
			test(t)
		} else {
			label := fmt.Sprintf("config=%x", tv.odoh_config)
			t.Run(label, test)
		}
	}
}

func TestVectorGenerate(t *testing.T) {
	// This is the mandatory HPKE ciphersuite
	supportedKEMs := []hpke.KEMID{hpke.DHKEM_X25519}
	supportedKDFs := []hpke.KDFID{hpke.KDF_HKDF_SHA256}
	supportedAEADs := []hpke.AEADID{hpke.AEAD_AESGCM128}

	vectors := make([]testVector, 0)
	for _, kem_id := range supportedKEMs {
		for _, kdf_id := range supportedKDFs {
			for _, aead_id := range supportedAEADs {
				vectors = append(vectors, generateTestVector(t, kem_id, kdf_id, aead_id))
			}
		}
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyTestVectors(t, encoded, false)

	// Write them to a file if requested
	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) > 0 {
		err = ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerify(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyTestVectors(t, encoded, true)
}
