## AWS Proxy
### Overview
This is a simple program that runs a server that can receive
a request to any AWS service and resign the request with new
credentials before sending it to the originally intended 
service

### Usage
Build:
```
go build .
```

Run:
```
aws-proxy [-port <port>] [-verbose] [-aws-partition <partition>]
```
* `-port` specifies the port to run the proxy server on
* `-verbose` will add more verbose logging
* `-aws-partition` aws partition to use

Credentials are picked up from the environment, following the 
standard [AWS credential provider chain](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#specifying-credentials)

Now you can point your SDK at the locally running server to get request resigned. Example with the AWS CLI:

```bash
aws --profile unauthorized-profile s3 cp \
    --endpoint-url http://localhost:8080 \
    /tmp/some/local/file.txt \
    s3://bucket/key.txt
```

### Current Limitations
- Only works for AWS requests sent over https. Original request must be signed with sigv4 auth
- Uses both aws golang sdk v2 and v1 because of limitations 
  around retrieving service endpoints in v2

### TODOs:
- Improve logging framework
- Ensure the proxy sub-module can be used on its own