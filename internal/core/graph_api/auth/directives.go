package auth

import (
	"context"
	"github.com/99designs/gqlgen/graphql"
	"github.com/juliangruber/go-intersect"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func Aws_auth(ctx context.Context, obj interface{}, next graphql.Resolver, cognito_groups []string) (interface{}, error) {
	user := ForContext(ctx)

	hasPermission := len(intersect.Simple(user.Groups, cognito_groups).([]interface{})) > 0
	if hasPermission == false {
	// block calling the next resolver
	return nil, gqlerror.Errorf("Access denied")
	}

	// or let it pass through
	return next(ctx)
}
