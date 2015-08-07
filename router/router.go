package main

import (
	"flag"
	"net"
	"os"
	"runtime"

	"github.com/dustywilson/tanuki"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var routerAddr = flag.String("r", "127.0.0.1:43968", "Router server IP:PORT")

type service struct {
	hostname string
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	hostname, _ := os.Hostname()

	l, err := net.Listen("tcp", *routerAddr)
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer()
	tanuki.RegisterRouterServer(grpcServer, &service{hostname: hostname})
	grpcServer.Serve(l)
}

func (s *service) Send(ctx context.Context, envelope *tanuki.Envelope) (*tanuki.StatusResponse, error) {
	// do something with "envelope" (queue it for delivery, or whatever)
	// the returned Envelope should be signed by the router itself and should provide delivery status as best as we can provide
	return nil, nil
}

func (s *service) Receive(subreq *tanuki.SubscriptionRequest, stream tanuki.Router_ReceiveServer) error {
	return nil
}
