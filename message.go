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
	"io"
	"log"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/sha3"
)

// MarshalMessage packages, encrypts, and signs outgoing structured messages
func MarshalMessage(senderPrivateKey *rsa.PrivateKey, providePublicKey bool, receiverPublicKey *rsa.PublicKey, message proto.Message) (*EncryptedEnvelope, error) {
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

	payloadNonce := make([]byte, gcm.NonceSize())
	rand.Read(payloadNonce)
	payloadEncrypted := gcm.Seal(nil, payloadNonce, payload, nil) // ???: should we be making use of the data argument (position 4)

	payloadSignatureOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	payloadSignatureHash := sha3.Sum256(payloadEncrypted)
	payloadSignature, err := rsa.SignPSS(rand.Reader, senderPrivateKey, crypto.SHA3_256, payloadSignatureHash[:], payloadSignatureOptions)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	var publicKeyNonce []byte
	var publicKeyEncrypted []byte
	if providePublicKey {
		senderPublicKeyMarshaled, err := x509.MarshalPKIXPublicKey(senderPrivateKey.Public().(*rsa.PublicKey))
		if err != nil {
			log.Println(err)
			return nil, errors.New("Something happened.")
		}
		publicKeyNonce = make([]byte, gcm.NonceSize())
		rand.Read(publicKeyNonce)
		publicKeyEncrypted = gcm.Seal(nil, publicKeyNonce, senderPublicKeyMarshaled, nil)
	}

	request := &EncryptedEnvelope{
		Key:              keyOut,
		PublicKeyNonce:   publicKeyNonce,
		PublicKey:        publicKeyEncrypted,
		PayloadNonce:     payloadNonce,
		Payload:          payloadEncrypted,
		PayloadSignature: payloadSignature,
	}

	return request, nil
}

// UnmarshalMessage decrypts, verifies, and unwraps inbound structured messages
//
// senderPublicKeyExtractor should be nil unless you need to extract the key from the payload itself.
func UnmarshalMessage(myPrivateKey *rsa.PrivateKey, theirPublicKey *rsa.PublicKey, theirPublicKeyAllowUpdate bool, message *EncryptedEnvelope, dst proto.Message) error {
	sha := sha3.New256()
	keyOut, err := rsa.DecryptOAEP(sha, rand.Reader, myPrivateKey, message.Key, nil) // WARNING: do not reuse this key
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	if theirPublicKeyAllowUpdate && message.PublicKeyNonce != nil && message.PublicKey != nil {
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

		publicKey, err := gcm.Open(nil, message.PublicKeyNonce, message.PublicKey, nil) // ???: should we be making use of the data argument (position 4)
		if err != nil {
			log.Println(err)
			return errors.New("Something happened.")
		}

		parsedPublicKey, err := x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			log.Println(err)
			return errors.New("Something happened.")
		}

		*theirPublicKey = *(parsedPublicKey.(*rsa.PublicKey))
	}

	if theirPublicKey != nil {
		payloadSignatureOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
		payloadSignatureHash := sha3.Sum256(message.Payload)
		err = rsa.VerifyPSS(theirPublicKey, crypto.SHA3_256, payloadSignatureHash[:], message.PayloadSignature, payloadSignatureOptions)
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

	payload, err := gcm.Open(nil, message.PayloadNonce, message.Payload, nil) // ???: should we be making use of the data argument (position 4)
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	err = proto.Unmarshal(payload, dst)
	if err != nil {
		log.Println(err)
		return errors.New("Something happened.")
	}

	return nil
}

// SendRecvr has both Send() and Recv() using EncryptedEnvelope
type SendRecvr interface {
	Send(*EncryptedEnvelope) error
	Recv() (*EncryptedEnvelope, error)
}

// BidirectionalStreamer handles everything
func BidirectionalStreamer(myPrivateKey *rsa.PrivateKey, providePublicKeyOnFirstMessage bool, theirPublicKey *rsa.PublicKey, receiverPublicKeyAllowUpdate bool, stream SendRecvr) (inbound <-chan proto.Message, outbound chan<- proto.Message, quit <-chan struct{}, errs <-chan error) {
	providePublicKey := providePublicKeyOnFirstMessage

	inboundChan := make(chan proto.Message)
	outboundChan := make(chan proto.Message)
	quitChan := make(chan struct{})
	errChan := make(chan error)

	go func(stream SendRecvr) {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				log.Println("streamRecv EOF")
				close(quitChan)
				return
			}
			if err != nil {
				errChan <- err
				close(quitChan)
				return
			}
			message := &IdentityRegistrationRequest{}
			err = UnmarshalMessage(myPrivateKey, theirPublicKey, receiverPublicKeyAllowUpdate, in, message)
			if err != nil {
				errChan <- err
				return
			}
			inboundChan <- message
		}
	}(stream)

	go func(stream SendRecvr) {
		for {
			select {
			case out, ok := <-outboundChan:
				if !ok {
					log.Println("outboundChan closed")
					close(quitChan)
					return
				}
				message, err := MarshalMessage(myPrivateKey, providePublicKey, theirPublicKey, out)
				if err != nil {
					errChan <- err
					return
				}
				providePublicKey = false

				err = stream.Send(message)
				if err == io.EOF {
					log.Println("streamSend EOF")
					return
				}
				if err != nil {
					errChan <- err
					close(quitChan)
					return
				}
			case <-quitChan:
				log.Println("quitChan closed")
				close(inboundChan)
				return
			}
		}
	}(stream)

	return inboundChan, outboundChan, quitChan, errChan
}
