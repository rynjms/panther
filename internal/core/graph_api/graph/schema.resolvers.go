package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"

	"github.com/panther-labs/panther/internal/core/graph_api/auth"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/generated"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/loaders"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/model"
	"github.com/vektah/gqlparser/gqlerror"
)

func (r *mutationResolver) CreateTodo(ctx context.Context, input model.NewTodo) (*model.Todo, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Todos(ctx context.Context) ([]*model.Todo, error) {
	user := auth.ForContext(ctx)
	fmt.Println(user.Subject)

	//var listOutput []*models.SourceIntegration
	//var listInput = &models.LambdaInput{
	//	ListIntegrations: &models.ListIntegrationsInput{},
	//}
	//if err := genericapi.Invoke(client, "panther-source-api", listInput, &listOutput); err != nil {
	//	panic(err)
	//}
	//
	//fmt.Println(*listOutput[0])

	var payload = []*model.Todo{{
		ID:   "1",
		Text: "hello",
		Done: false,
		User: nil,
	}, {
		ID:   "2",
		Text: "hello 2",
		Done: true,
		User: nil,
	}}

	return payload, nil
}

func (r *todoResolver) Groups(ctx context.Context, obj *model.Todo) ([]*model.Group, error) {
	groups, err := loaders.For(ctx).GroupLoader.Load(obj.ID)
	if err != nil {
		return nil, gqlerror.Errorf(err.Error())
	}
	return groups, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

// Todo returns generated.TodoResolver implementation.
func (r *Resolver) Todo() generated.TodoResolver { return &todoResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type todoResolver struct{ *Resolver }
