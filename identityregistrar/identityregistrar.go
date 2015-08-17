package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	}

	// FIXME: this should register with something that proves this service instance has any authority (should that service block insufficiently-sized keys?)

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
	// func DecryptOAEP(hash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) (msg []byte, err error)
	sha := sha256.New()
	keyOut, err := rsa.DecryptOAEP(sha, rand.Reader, ir.privateKey, in.Key, nil) // WARNING: do not reuse this key
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	// ???: Do we care to test the symmetric key strength before continuing?  We could decide it's too weak and just kill the client in order to enforce some reasonable minimum level of security.

	block, err := aes.NewCipher(keyOut)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Something happened.")
	}

	return nil, nil
}

func (ir *identityRegistrar) Prove(ctx context.Context, in *tanuki.IdentityRegistrationProofEncrypted) (*tanuki.IdentityRegistrationTicketEncrypted, error) {
	return nil, nil
}
