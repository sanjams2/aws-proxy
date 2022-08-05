package main

import (
	"aws-proxy/proxy"
	"context"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"log"
	"net/http"
	"time"
)

func main() {

	port := flag.Int("port", 8080, "port to run proxy on")
	debug := flag.Bool("verbose", false, "enable debug logs")
	partition := flag.String("aws-partition", "aws", "aws partition to use")
	flag.Parse()

	addr := fmt.Sprintf("localhost:%d", *port)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolver(defaultEndpointResolver(*partition)),
	)
	if err != nil {
		panic(err)
	}

	handler := proxy.NewProxyHandler(http.DefaultClient, &cfg, *debug)

	server := http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 60 * time.Second,
	}
	fmt.Printf("Listening on %s\n", addr)
	log.Panic(server.ListenAndServe())
}
