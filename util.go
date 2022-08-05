package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
)

// Unfortunately there is no good way to resolve endpoints for a given service
// and region. We fallback to the v1 SDK to resolve endpoints.
func defaultEndpointResolver(partition string) aws.EndpointResolver {
	var awsPartition endpoints.Partition
	if partition == "aws" {
		awsPartition = endpoints.AwsPartition()
	} else if partition == "aws-cn" {
		awsPartition = endpoints.AwsCnPartition()
	} else if partition == "aws-gov" {
		awsPartition = endpoints.AwsUsGovPartition()
	} else if partition == "aws-iso" {
		awsPartition = endpoints.AwsIsoPartition()
	} else if partition == "aws-iso-b" {
		awsPartition = endpoints.AwsIsoBPartition()
	} else {
		panic(fmt.Sprintf("Unknown partition: %s", partition))
	}
	return aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
		endpoint, err := awsPartition.EndpointFor(service, region)
		if err != nil {
			return aws.Endpoint{}, err
		}
		return aws.Endpoint{
			URL:           endpoint.URL,
			PartitionID:   endpoint.PartitionID,
			SigningName:   endpoint.SigningName,
			SigningRegion: endpoint.SigningRegion,
			SigningMethod: endpoint.SigningMethod,
		}, nil
	})
}
