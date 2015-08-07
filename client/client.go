package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/dustywilson/tanuki"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var routerAddr = flag.String("r", "127.0.0.1:43968", "Router server IP:PORT")
var mediator1Addr = flag.String("m1", "127.0.0.1:43969", "Mediator 1 server IP:PORT")
var mediator2Addr = flag.String("m2", "127.0.0.1:43970", "Mediator 2 server IP:PORT")
var forwarderAddr = flag.String("f", "127.0.0.1:43971", "Forwarder server IP:PORT")
var recipientCN = flag.String("cn", "", "Recipient Common Name")

type service struct {
	hostname string
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	// conn, err := grpc.Dial(*routerAddr)
	// if err != nil {
	// 	panic(err)
	// }

	// these should be in parallel, not serial, for speed...
	m1, e1, err := getMediation(*mediator1Addr, *recipientCN)
	if err != nil {
		panic(err)
	}
	m2, e2, err := getMediation(*mediator2Addr, *recipientCN)
	if err != nil {
		panic(err)
	}

	fmt.Println(m1, e1)
	fmt.Println(m2, e2)
	os.Exit(1)

	for {
		<-time.After(time.Second * 30)
		log.Println("[Main tick]")
	}
}

func getMediation(mediatorAddr string, recipientCN string) (string, []byte, error) {
	conn, err := grpc.Dial(mediatorAddr)
	if err != nil {
		panic(err)
	}
	c := tanuki.NewMediatorClient(conn)
	hs, err := c.Handshake(context.Background(), &tanuki.MediatorHandshakeRequest{})
	if err != nil {
		return "", nil, err
	}
	// this probably should get unencrypted right here, presuming we're encrypted for this client to decrypt
	return "HELLO", hs.EncryptedResponse, nil
}
