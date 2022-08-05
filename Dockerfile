FROM public.ecr.aws/amazonlinux/amazonlinux:2

RUN yum install -y go

RUN mkdir /aws-proxy
WORKDIR /aws-proxy
COPY go.mod .
COPY go.sum .

RUN go env -w GOPROXY=direct
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/aws-proxy
ENTRYPOINT [ "/go/bin/aws-proxy" ]