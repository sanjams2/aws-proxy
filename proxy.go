package main

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	headersToScrub = map[string]struct{}{
		"Authorization":        {},
		"X-Amz-Security-Token": {},
	}
	authUnsignableHeaders = map[string]struct{}{
		"Expect":          {},
		"Accept-Encoding": {},
		"Content-Length":  {},
	}
)

type proxyHandler struct {
	signer    *v4.Signer
	client    *http.Client
	partition endpoints.Partition
	debug     bool
}

func NewProxyHandler(client *http.Client, creds *credentials.Credentials, partition endpoints.Partition, debug bool) http.Handler {
	signer := v4.NewSigner(creds, func(s *v4.Signer) {
		//s.Debug = aws.LogDebugWithSigning
		s.Debug = aws.LogOff
		s.Logger = aws.NewDefaultLogger()
	})
	return &proxyHandler{
		signer:    signer,
		client:    client,
		partition: partition,
		debug:     debug,
	}
}

func (d *proxyHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// determine request region and service
	region, service := d.getRequestScope(request)
	if region == "" || service == "" {
		fmt.Println("Unable to determine region/service of request. Request may not be signed")
		writer.WriteHeader(400)
		return
	}
	fmt.Printf("Received request for region: %s, service: %s\n", region, service)

	// Determine awsEndpoint from service and region of request
	awsEndpoint, err := d.partition.EndpointFor(service, region)
	if err != nil {
		fmt.Printf("Error determining awsEndpoint: %v\n", err)
		writer.WriteHeader(500)
		return
	}

	// Copy incoming request to a new outgoing request
	d.logHeaders("Original Headers", request)
	proxyReq, err := d.initializeDownstreamRequest(request, awsEndpoint)
	if err != nil {
		fmt.Printf("Error creating proxy request: %v\n", err)
		writer.WriteHeader(500)
		return
	}

	// Load the body
	// If we use the aws-go-sdk-v2, we dont need to load the whole body like this
	// See: SignHTTP method, which accepts the payload hash as a parameter
	// S3 provides the payload hash as an http Header which means we do not need to load
	// the whole body
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		fmt.Printf("Error reading request body: %v\n", err)
		writer.WriteHeader(500)
		return
	}
	d.log("Body", func() string { return string(body) })

	// Sign the request
	scrubbedHeaders := d.scrubUnsignableHeaders(proxyReq)
	_, err = d.signer.Sign(proxyReq, aws.ReadSeekCloser(bytes.NewReader(body)), service, awsEndpoint.SigningRegion, time.Now())
	if err != nil {
		fmt.Printf("Error signing request: %v\n", err)
		writer.WriteHeader(500)
		return
	}
	d.addHeaders(proxyReq, scrubbedHeaders)
	d.logHeaders("Proxy Request Headers", proxyReq)

	// Execute the downstream request
	resp, err := d.client.Do(proxyReq)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		writer.WriteHeader(500)
		return
	}

	// Write response
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Println("error closing body", err)
		}
	}()
	fmt.Printf("Received response with status: %d\n", resp.StatusCode)
	for h, val := range resp.Header {
		writer.Header()[h] = val
	}
	writer.WriteHeader(resp.StatusCode)
	// Streams response, may get tricky if the downstream service is slow and
	// golang automagically turns the request response into a chunked-encoded response
	if _, err = io.Copy(writer, resp.Body); err != nil {
		panic(err)
	}
}

// Copies an *http.Request to a new *http.Request that can be used to make outbound calls
// Note: only headers are copied. Body is not copied
func (d *proxyHandler) initializeDownstreamRequest(request *http.Request, awsEndpoint endpoints.ResolvedEndpoint) (*http.Request, error) {
	// TODO: maybe consider httpp requests
	host := strings.TrimPrefix(awsEndpoint.URL, "https://")
	url := fmt.Sprintf("https://%s%s", host, request.RequestURI)

	if d.debug {
		fmt.Println("URL:", url)
		fmt.Println("Request Method:", request.Method)
	}
	proxyReq, err := http.NewRequest(request.Method, url, nil)
	if err != nil {
		return nil, err
	}

	// Copy all headers, except those that we explicitly dont want
	proxyReq.Header = make(http.Header)
	for h, val := range request.Header {
		if _, shouldSkip := headersToScrub[h]; !shouldSkip {
			proxyReq.Header[h] = val
		}
	}

	// If Content-Length header, set it on the request
	if contentLength := request.Header.Get("Content-Length"); contentLength != "" {
		i, err := strconv.Atoi(contentLength)
		if err != nil {
			fmt.Printf("error converting content length: %v\n", contentLength)
		} else {
			proxyReq.ContentLength = int64(i)
		}
	}

	// Set host
	proxyReq.Host = host

	return proxyReq, nil
}

// Returns the region and service of a request
func (d *proxyHandler) getRequestScope(request *http.Request) (string, string) {
	// TODO: optimize this a bit to remove need to create string arrays
	authHeaders := strings.Split(request.Header.Get("Authorization"), " ")
	var region, service string
	for _, h := range authHeaders {
		if strings.HasPrefix(h, "Credential=") {
			credentialPieces := strings.Split(h, "/")
			region, service = credentialPieces[2], credentialPieces[3]
		}
	}
	return region, service
}

func (d *proxyHandler) scrubUnsignableHeaders(req *http.Request) http.Header {
	scrubbedHeaders := make(http.Header)
	for k, v := range req.Header {
		if _, isUnsignable := authUnsignableHeaders[k]; isUnsignable {
			scrubbedHeaders[k] = v
			req.Header.Del(k)
		}
	}
	return scrubbedHeaders
}

func (d *proxyHandler) addHeaders(req *http.Request, headers http.Header) {
	for k, v := range headers {
		req.Header[k] = v
	}
}

func (d *proxyHandler) logHeaders(title string, request *http.Request) {
	if d.debug {
		fmt.Printf("---------- %s ------------", title)
		for k, v := range request.Header {
			fmt.Println(k, v)
		}
		fmt.Println("----------------------")
	}
}

func (d *proxyHandler) log(title string, body func() string) {
	if d.debug {
		fmt.Printf("---------- %s ------------", title)
		fmt.Println(body())
		fmt.Println("----------------------")
	}
}
