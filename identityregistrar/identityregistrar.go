package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/dustywilson/tanuki"
	"github.com/golang/protobuf/proto"
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
	message := tanuki.EncryptedEnvelope(*in)
	request := &tanuki.IdentityRegistrationRequest{}
	err := tanuki.UnmarshalMessage(
		ir.privateKey,
		nil,
		func(irr proto.Message) ([]byte, error) {
			return irr.(*tanuki.IdentityRegistrationRequest).PublicKey, nil
		},
		&message,
		request,
	)
	if err != nil {
		return nil, err
	}

	return nil, errors.New("Seems good, but the princess isn't yet in this castle.")
}

func (ir *identityRegistrar) Prove(ctx context.Context, in *tanuki.IdentityRegistrationProofEncrypted) (*tanuki.IdentityRegistrationTicketEncrypted, error) {
	return nil, nil
}
