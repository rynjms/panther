package main

import (
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/panther-labs/panther/internal/core/graph_api/auth"
	"github.com/panther-labs/panther/internal/core/graph_api/graph"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/generated"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/loaders"
	"log"
	"net/http"
	"os"
)

const defaultPort = "8080"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	c := generated.Config{Resolvers: &graph.Resolver{}}
	c.Directives.Aws_auth = auth.Aws_auth

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(c))

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", auth.Middleware(loaders.Middleware(srv)))

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
