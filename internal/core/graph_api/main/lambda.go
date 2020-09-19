package main

import (
	"context"
	"github.com/panther-labs/panther/internal/core/graph_api/auth"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/loaders"
	"log"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/gorillamux"
	"github.com/gorilla/mux"
	"github.com/panther-labs/panther/internal/core/graph_api/graph"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/generated"
)

var muxAdapter *gorillamux.GorillaMuxAdapter
var router *mux.Router

func init() {
	router = mux.NewRouter()

	config := generated.Config{Resolvers: &graph.Resolver{}}
	config.Directives.Aws_auth = auth.Aws_auth

	server := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	router.Handle("/", playground.Handler("GraphQL playground", "/query"))
	router.Handle("/query", auth.Middleware(loaders.Middleware(server)))

	muxAdapter = gorillamux.New(router)
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	rsp, err := muxAdapter.ProxyWithContext(ctx, req)
	if err != nil {
		log.Println(err)
	}
	return rsp, err
}

func main() {
	lambda.Start(Handler)
}

// for local development
//func main() {
//	log.Printf("connect to http://localhost:8080/ for GraphQL playground")
//	log.Fatal(http.ListenAndServe(":8080", router))
//}
