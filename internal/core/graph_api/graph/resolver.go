package graph

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
)

//go:generate go run github.com/99designs/gqlgen

// This file will not be regenerated automatically.
//

var (
	awsRegion  = "eu-central-1"
	awsSession = session.Must(session.NewSession())
	client     = lambda.New(awsSession, &aws.Config{Region: aws.String(awsRegion)})
)

type Resolver struct{}
