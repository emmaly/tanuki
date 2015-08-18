package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"github.com/dustywilson/tanuki"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type identityRegistrar struct {
	id         []byte
	privateKey *rsa.PrivateKey
	secretKey  []byte
}

var debug = flag.Bool("debug", false, "Show debugging output?")
var identityRegistrarAddr = flag.String("ir", "127.0.0.1:43972", "Identity Registrar server IP:PORT")
var privateKeySize = flag.Int("kb", 4096, "Key size in bits")

var serviceName = "identityregistrar" // ???

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	fmt.Printf("Generating internal secret key... ")
	secretKey := make([]byte, 16)
	rand.Read(secretKey)
	fmt.Println("done.")

	fmt.Printf("Generating %d-bit private key... ", *privateKeySize)
	privateKey, err := tanuki.NewPrivateKey(*privateKeySize)
	if err != nil {
		fmt.Println(" ERROR.")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("done.")

	if *debug {
		pk := tanuki.PublicKeyFingerprint(privateKey.Public().(*rsa.PublicKey))
		fmt.Printf("Public Key Fingerprint: %s\n", pk.String())
		fmt.Printf("Public Key:\n\tE: %d\n\tN: %s\n", privateKey.Public().(*rsa.PublicKey).E, privateKey.Public().(*rsa.PublicKey).N)
	}

	// FIXME: this should register with something that proves this service instance has any authority (should that service block insufficiently-sized keys?)
	err = tanuki.RegisterService(serviceName, *identityRegistrarAddr, privateKey.Public().(*rsa.PublicKey))
	if err != nil {
		fmt.Println(" ERROR.")
		fmt.Println(err)
		os.Exit(1)
	}
	// FIXME: this should register with something to inject this service instance into the discovery system (should that service block insufficiently-sized keys?)

	grpcServer := grpc.NewServer()
	tanuki.RegisterIdentityRegistrationServer(grpcServer, &identityRegistrar{
		id:         tanuki.PublicKeyFingerprint(privateKey.Public().(*rsa.PublicKey)),
		privateKey: privateKey,
		secretKey:  secretKey,
	})

	l, err := net.Listen("tcp", *identityRegistrarAddr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ListenAndServe on %s.\n", *identityRegistrarAddr)
	panic(grpcServer.Serve(l))
}

func (ir *identityRegistrar) Register(ctx context.Context, in *tanuki.IdentityRegistrationRequestEncrypted) (*tanuki.IdentityRegistrationChallengeEncrypted, error) {
	// FIXME: it seems that for a lot of this code, we could throw it in a separate function or set of functions since we'll be doing pretty much exactly this over and over and over in all of our RPC functions and services

	sha := sha3.New256()
	keyOut, err := rsa.DecryptOAEP(sha, rand.Reader, ir.privateKey, in.Key, nil) // WARNING: do not reuse this key
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	aesBlock, err := aes.NewCipher(keyOut)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	payload, err := gcm.Open(nil, in.Nonce, in.Payload, nil) // ???: should we be making use of the data argument (position 4)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	request := &tanuki.IdentityRegistrationRequest{}
	err = proto.Unmarshal(payload, request)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	userPublicKey, err := x509.ParsePKIXPublicKey(request.PublicKey)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}
	signatureOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	signatureHash := sha3.Sum256(in.Payload)
	err = rsa.VerifyPSS(userPublicKey.(*rsa.PublicKey), crypto.SHA3_256, signatureHash[:], in.Signature, signatureOptions)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	log.Printf("Message:  <  %+v  >\n", request) // FIXME: remove

	return nil, errors.New("Seems good, but the princess isn't yet in this castle.")
}

func (ir *identityRegistrar) Prove(ctx context.Context, in *tanuki.IdentityRegistrationProofEncrypted) (*tanuki.IdentityRegistrationTicketEncrypted, error) {
	return nil, nil
}
