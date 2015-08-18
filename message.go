package tanuki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/sha3"
)

// MarshalMessage packages, encrypts, and signs outgoing structured messages
func MarshalMessage(senderPrivateKey *rsa.PrivateKey, receiverPublicKey *rsa.PublicKey, message proto.Message) (*EncryptedEnvelope, error) {
	key := make([]byte, 32) // must be a multiple of 16
	rand.Read(key)
	fmt.Printf("KEY: %x\n", key)

	sha := sha3.New256()
	keyOut, err := rsa.EncryptOAEP(sha, rand.Reader, receiverPublicKey, key, nil) // WARNING: do not reuse this key
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	payload, err := proto.Marshal(message)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	payloadEncrypted := gcm.Seal(nil, nonce, payload, nil) // ???: should we be making use of the data argument (position 4)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	signatureOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	signatureHash := sha3.Sum256(payloadEncrypted)
	signature, err := rsa.SignPSS(rand.Reader, senderPrivateKey, crypto.SHA3_256, signatureHash[:], signatureOptions)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	request := &EncryptedEnvelope{
		Key:       keyOut,
		Nonce:     nonce,
		Payload:   payloadEncrypted,
		Signature: signature,
	}

	return request, nil
}

// UnmarshalMessage decrypts, verifies, and unwraps inbound structured messages
//
// senderPublicKeyExtractor should be nil unless you need to extract the key from the payload itself.
func UnmarshalMessage(receiverPrivateKey *rsa.PrivateKey, senderPublicKey *rsa.PublicKey, senderPublicKeyExtractor func(proto.Message) ([]byte, error), message proto.Message, dst proto.Message) error {
	in := message.(*EncryptedEnvelope)

	sha := sha3.New256()
	keyOut, err := rsa.DecryptOAEP(sha, rand.Reader, receiverPrivateKey, in.Key, nil) // WARNING: do not reuse this key
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	aesBlock, err := aes.NewCipher(keyOut)
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	payload, err := gcm.Open(nil, in.Nonce, in.Payload, nil) // ???: should we be making use of the data argument (position 4)
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	err = proto.Unmarshal(payload, dst)
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	if senderPublicKeyExtractor != nil {
		extractedPublicKey, err := senderPublicKeyExtractor(dst)
		parsedPublicKey, err := x509.ParsePKIXPublicKey(extractedPublicKey)
		if err != nil {
			log.Println(err)
			return errors.New("Something happened.")
		}
		senderPublicKey = parsedPublicKey.(*rsa.PublicKey)
	}

	if senderPublicKey != nil {
		signatureOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
		signatureHash := sha3.Sum256(in.Payload)
		err = rsa.VerifyPSS(senderPublicKey, crypto.SHA3_256, signatureHash[:], in.Signature, signatureOptions)
		if err != nil {
			dst = nil
			log.Println(err)
			return errors.New("Something happened.")
		}
	} else {
		// ???: What do we do?  We could fail right here since it's impossible to
		//      verify the signature without the public key.  Or we could trust the
		//      caller that they don't care.  But do we trust the caller to not
		//      care?  That seems very iffy.  I think we should implode here.
		dst = nil
		log.Println("The caller didn't supply a public key, so we can't verify the signature.")
		return errors.New("Something happened.")
		// ... the other option is to just let continue along.  I think maybe that's foolish.
	}

	return nil
}
