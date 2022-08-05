package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"log"
	"net/http"
	"time"
)


func main() {
	addr := "localhost:8080"
	debug := false

	creds := credentials.NewEnvCredentials()

	handler := NewProxyHandler(http.DefaultClient, creds, endpoints.AwsPartition(), debug)

	server := http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 60*time.Second,
	}
	fmt.Printf("Listening on %s\n", addr)
	log.Panic(server.ListenAndServe())
}
