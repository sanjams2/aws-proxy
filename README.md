## AWS Proxy
### Overview
This is a simple program that can proxy any AWS SigV4 request, resign with specified credentials, 
and send it to the originally intended service.

How is this different from https://github.com/awslabs/aws-sigv4-proxy? The `aws-sigv4-proxy` library
requires that the entire request body be read and loaded into memory. This is due to a limitation in 
the aws golang sdk v1. This package instead utilizes the v2 sdk and therefore can detect
if the body needs to be read entirely or not. This is particularly useful when sending large objects
to S3. 

### Usage
First, clone the repository. Then...

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

#### Docker
Build the image
```bash
docker build . -t aws-proxy
```

Run the image
```bash
docker run \
-p 8080:8080 \
-v ~/.aws:/root/.aws \
aws-proxy -port 8080
```

### Current Limitations
- Only works for AWS requests sent over https. Original request must be signed with sigv4 auth
- Uses both aws golang sdk v2 and v1 because of limitations 
  around retrieving service endpoints in v2

### TODOs:
- Improve logging framework
- Ensure the proxy sub-module can be used on its own