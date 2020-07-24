package odoh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/cisco/go-hpke"
	"io"
	"testing"
)

/*
This collections of tests are used to ensure that the objects and encryption from Go lang
can successfully inter-operate and can be read by the rust libraries.
 */

func Test_Golang_Encryption_For_Rust_Decryption(t *testing.T) {
	/*
	This test assumes the following:

	Go lang based client using the odoh library first uses the public key given by a rust target server
	and encrypts the message. The goal of this test is to assert the following:

	1. A valid serialized ObliviousDNSPublicKey from Rust can be converted into the corresponding object.
	2. The encryption of a message can happen successfully.
	 */

	rustProvidedPublicKeyHex := "0020000100010020425577cf5a8a41cd45f91e2484c606a1ee00e8ce7534a3913a359c4046d3905b"
	rustProvidedPublicKeyBytes, err := hex.DecodeString(rustProvidedPublicKeyHex)

	if err != nil {
		t.Fatalf("Failed to decode the hex encoded public key to byte array")
	}

	fmt.Printf("%v\n", rustProvidedPublicKeyBytes)

	odohPkFromRustBytes := UnMarshalObliviousDNSPublicKey(rustProvidedPublicKeyBytes)

	fmt.Printf("ODOH PK : %v\n", odohPkFromRustBytes)
}

func Test_Golang_ODOH_KeyPair_Generation_and_Serialize(t *testing.T) {
	kemID := hpke.DHKEM_X25519// 0x0020
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

	targetKeyBytes := targetKey.Marshal()

	fmt.Printf("ODOH PK : %v\n", targetKeyBytes)

	targetKeyBytesHex := hex.EncodeToString(targetKeyBytes)
	fmt.Printf("ODOH PK : %v\n", targetKeyBytesHex)
}