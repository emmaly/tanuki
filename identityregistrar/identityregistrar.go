package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"github.com/dustywilson/tanuki"
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

func (ir *identityRegistrar) Register(stream tanuki.IdentityRegistration_RegisterServer) error {
	theirPublicKey := new(rsa.PublicKey)
	fmt.Printf("EH? %t\n", theirPublicKey == nil)
	inbound, outbound, quit, errs := tanuki.BidirectionalStreamer(ir.privateKey, false, theirPublicKey, true, stream)

	for {
		log.Printf("THEIR PUBLIC KEY loop: %+v\n", theirPublicKey)
		select {
		case in, ok := <-inbound:
			if !ok {
				close(outbound)
				log.Println("CLOSED INBOUND")
				return errors.New("Closed inbound")
			}
			log.Printf("REQUEST:  <  %+v  >\n", in) // FIXME: remove
			log.Printf("THEIR PUBLIC KEY received: %+v\n", theirPublicKey)
		case <-quit:
			log.Println("QUIT")
			return errors.New("Quit")
		case err := <-errs:
			log.Printf("ERROR: %s\n", err)
		}
	}

	// for {
	// 	in, err := stream.Recv()
	// 	if err == io.EOF {
	// 		return nil
	// 	}
	// 	if err != nil {
	// 		return err
	// 	}
	// 	request := &tanuki.IdentityRegistrationRequest{}
	// 	err = tanuki.UnmarshalMessage(
	// 		ir.privateKey,
	// 		nil,
	// 		func(irr proto.Message) ([]byte, error) {
	// 			return irr.(*tanuki.IdentityRegistrationRequest).PublicKey, nil
	// 		},
	// 		in,
	// 		request,
	// 	)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	log.Printf("REQUEST:  <  %+v  >\n", request) // FIXME: remove
	//
	// 	if err = stream.Send(nil); err != nil {
	// 		return err
	// 	}
	// }
}

func (ir *identityRegistrar) Prove(ctx context.Context, in *tanuki.EncryptedEnvelope) (*tanuki.EncryptedEnvelope, error) {
	return nil, nil
}
