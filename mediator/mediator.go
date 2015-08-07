package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/dustywilson/tanuki"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var mediatorPool = flag.Int("p", 1, "Pool: 1 or 2")
var mediator1Addr = flag.String("m1", "127.0.0.1:43969", "Mediator 1 server IP:PORT")
var mediator2Addr = flag.String("m2", "127.0.0.1:43970", "Mediator 2 server IP:PORT")

type mediator struct {
	hostname string
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())
	hostname, _ := os.Hostname()

	var serverAddr string
	switch *mediatorPool {
	case 1:
		serverAddr = *mediator1Addr
	case 2:
		serverAddr = *mediator2Addr
	}

	fmt.Printf("%d = %s\n", *mediatorPool, serverAddr)

	l, err := net.Listen("tcp", serverAddr)
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer()
	tanuki.RegisterMediatorServer(grpcServer, &mediator{hostname: hostname})
	grpcServer.Serve(l)
}

func (s *mediator) Handshake(ctx context.Context, req *tanuki.MediatorHandshakeRequest) (*tanuki.MediatorHandshakeResponse, error) {
	res := &tanuki.MediatorHandshakeResponse{}
	return res, nil
}
