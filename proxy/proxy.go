package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/google/uuid"

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
	payloadSignatureHeaders = []string{
		"X-Amz-Content-Sha256",
	}
)

type proxyHandler struct {
	signer    *v4.Signer
	client    *http.Client
	config    *aws.Config
	debug     bool
}

func NewProxyHandler(client *http.Client, config *aws.Config, debug bool) http.Handler {
	signer := v4.NewSigner(func(s *v4.SignerOptions) {
		s.LogSigning = debug
		s.Logger = config.Logger
	})
	return &proxyHandler{
		signer:    signer,
		client:    client,
		config:    config,
		debug:     debug,
	}
}

func (d *proxyHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	reqId := uuid.New().String()

	// determine request region and service
	region, service := d.getRequestScope(request)
	if region == "" || service == "" {
		fmt.Printf("[%s] Unable to determine region/service of request. Request may not be signed\n", reqId)
		writer.WriteHeader(400)
		return
	}

	fmt.Printf("[%s] Received request for region: %s, service: %s\n", reqId, region, service)

	// Determine awsEndpoint from service and region of request
	awsEndpoint, err := d.config.EndpointResolver.ResolveEndpoint(service, region)
	if err != nil {
		fmt.Printf("[%s] Error determining awsEndpoint: %v\n", reqId, err)
		writer.WriteHeader(500)
		return
	}

	// Copy incoming request to a new outgoing request
	d.logHeaders("Original Headers", request)
	proxyReq, err := d.initializeDownstreamRequest(request, awsEndpoint)
	if err != nil {
		fmt.Printf("[%s] Error creating proxy request: %v\n", reqId, err)
		writer.WriteHeader(500)
		return
	}

	// Calculate the payload hash
	payloadHash, err := d.getPayloadHash(proxyReq)
	if err != nil {
		fmt.Printf("[%s] Error configuring downstream request body: %v\n", reqId, err)
		writer.WriteHeader(500)
		return
	}

	// Get signing credentials
	creds, err := d.config.Credentials.Retrieve(context.TODO())
	if err != nil {
		fmt.Printf("[%s] Error retrieving creds: %v\n", reqId, err)
		writer.WriteHeader(500)
		return
	}

	// Sign the request
	scrubbedHeaders := d.scrubUnsignableHeaders(proxyReq)
	if err = d.signer.SignHTTP(context.TODO(), creds, proxyReq, payloadHash, service, awsEndpoint.SigningRegion, time.Now()); err != nil {
		fmt.Printf("[%s] Error signing request: %v\n", reqId, err)
		writer.WriteHeader(500)
		return
	}
	d.addHeaders(proxyReq, scrubbedHeaders)
	d.logHeaders("Proxy Request Headers", proxyReq)

	// Execute the downstream request
	resp, err := d.client.Do(proxyReq)
	if err != nil {
		fmt.Printf("[%s] Error making request: %v\n", reqId, err)
		writer.WriteHeader(500)
		return
	}

	// Ensure body gets closed
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Println("error closing body", err)
		}
	}()
	fmt.Printf("[%s] Received response with status: %d\n", reqId, resp.StatusCode)

	// Write response
	for h, val := range resp.Header {
		writer.Header()[h] = val
	}
	writer.WriteHeader(resp.StatusCode)
	// Streams response, may get tricky if the downstream service is slow and
	// golang automagically turns the request response into a chunked-encoded response
	if _, err = io.Copy(writer, resp.Body); err != nil {
		fmt.Println("error writing body", err)
	}
}

// Copies an *http.Request to a new *http.Request that can be used to make outbound calls
func (d *proxyHandler) initializeDownstreamRequest(request *http.Request, awsEndpoint aws.Endpoint) (*http.Request, error) {
	// TODO: maybe consider http requests
	host := strings.TrimPrefix(awsEndpoint.URL, "https://")
	url := fmt.Sprintf("https://%s%s", host, request.RequestURI)

	d.log("URL:", url)
	d.log("Request Method:", request.Method)

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

	// Set body
	proxyReq.Body = request.Body

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

// Calculate the payload hash of the request
// If the header Amzn-X-Payload-SHA256 exists, then this will be used and the
// body will not be read entirely into memory. If it's not set, then the
// body is read entirely, stored in memory, and then that byte array is set as
// the body on the request wrapped in a ioutil.NopCloser
func (d *proxyHandler) getPayloadHash(request *http.Request) (string, error) {
	for _, header := range payloadSignatureHeaders {
		if bodyContentSignature := request.Header.Get(header); bodyContentSignature != "" {
			d.log("Found payload signature header:", header, "Skipping setting body")
			return bodyContentSignature, nil
		}
	}
	// No header pre-set the payload signature, so calculate it ourselves
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return "", err
	}
	d.logSection("Body", string(body))
	request.Body = ioutil.NopCloser(bytes.NewReader(body))
	sha := sha256.Sum256(body)
	return fmt.Sprintf("%x", sha), nil
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
		fmt.Printf("---------- %s ------------\n", title)
		for k, v := range request.Header {
			fmt.Println(k, v)
		}
		fmt.Println("----------------------")
	}
}

func (d *proxyHandler) logSection(title, body string) {
	if d.debug {
		fmt.Printf("---------- %s ------------\n", title)
		fmt.Println(body)
		fmt.Println("----------------------")
	}
}

func (d *proxyHandler) log(msgs... string) {
	if d.debug {
		for _, m := range msgs {
			fmt.Printf("%v ", m)
		}
		fmt.Println()
	}
}
