package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/dustywilson/tanuki"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var debug = flag.Bool("debug", false, "Show debugging output?")
var routerAddr = flag.String("r", "127.0.0.1:43968", "Router server IP:PORT")
var mediator1Addr = flag.String("m1", "127.0.0.1:43969", "Mediator 1 server IP:PORT")
var mediator2Addr = flag.String("m2", "127.0.0.1:43970", "Mediator 2 server IP:PORT")
var forwarderAddr = flag.String("f", "127.0.0.1:43971", "Forwarder server IP:PORT")
var recipientCN = flag.String("cn", "", "Recipient Common Name")
var privateKeySize = flag.Int("kb", 4096, "Key size in bits")

type service struct {
	hostname string
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	registerIdentity()

	// conn, err := grpc.Dial(*routerAddr)
	// if err != nil {
	// 	panic(err)
	// }

	// these should be in parallel, not serial, for speed...
	// m1, e1, err := getMediation(*mediator1Addr, *recipientCN)
	// if err != nil {
	// 	panic(err)
	// }
	// m2, e2, err := getMediation(*mediator2Addr, *recipientCN)
	// if err != nil {
	// 	panic(err)
	// }
	//
	// fmt.Println(m1, e1)
	// fmt.Println(m2, e2)
	// os.Exit(1)
	//
	// for {
	// 	<-time.After(time.Second * 30)
	// 	log.Println("[Main tick]")
	// }
}

func registerIdentity() (interface{}, error) {
	fmt.Printf("Generating %d-bit private key... ", *privateKeySize)
	privateKey, err := tanuki.NewPrivateKey(*privateKeySize)
	if err != nil {
		fmt.Println(" ERROR.")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("done.")

	publicKeyMarshaled, err := x509.MarshalPKIXPublicKey(privateKey.Public().(*rsa.PublicKey))
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	innerNonce := make([]byte, 32)
	rand.Read(innerNonce)

	rawRequest := &tanuki.IdentityRegistrationRequest{
		SenderDomain:                  "bumbleserver.org",
		Nonce:                         innerNonce,
		PublicKey:                     publicKeyMarshaled,
		SomeSortOfAuthenticationProof: []byte("I'm queen of France!"),
	}

	identityRegistrarPublicKey, identityRegistrarAddr, err := tanuki.LookupService("identityregistrar")
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	message, err := tanuki.MarshalMessage(privateKey, identityRegistrarPublicKey, rawRequest)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	conn, err := grpc.Dial(identityRegistrarAddr)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	out := tanuki.IdentityRegistrationRequestEncrypted(*message)
	c := tanuki.NewIdentityRegistrationClient(conn)
	response, err := c.Register(context.Background(), &out)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	log.Printf("Message:  <  %+v  >\n", response) // FIXME: remove

	return nil, nil
}

// func getMediation(mediatorAddr string, recipientCN string) (string, []byte, error) {
// 	conn, err := grpc.Dial(mediatorAddr)
// 	if err != nil {
// 		panic(err)
// 	}
// 	c := tanuki.NewMediatorClient(conn)
// 	hs, err := c.Handshake(context.Background(), &tanuki.MediatorHandshakeRequest{})
// 	if err != nil {
// 		return "", nil, err
// 	}
// 	// this probably should get unencrypted right here, presuming we're encrypted for this client to decrypt
// 	return "HELLO", hs.EncryptedResponse, nil
// }
