package loaders

import (
	"fmt"
	"github.com/panther-labs/panther/internal/core/graph_api/graph/model"
	"time"
)

func getGroups(todoIds []string) [][]*model.Group {
	fmt.Println(todoIds)

	if len(todoIds) == 0 {
		return [][]*model.Group{}
	}
	groups := make([][]*model.Group, len(todoIds))
	for index, id := range todoIds {
		groups[index] = []*model.Group{{Name: fmt.Sprintf("Group %s", id)}}
	}
	return groups
}

func GenerateGroupLoader() GroupLoader {
	return *NewGroupLoader(GroupLoaderConfig{
		Wait:     2 * time.Millisecond,
		MaxBatch: 100,
		Fetch: func(keys []string) ([][]*model.Group, []error) {
			groups := getGroups(keys)
			errors := make([]error, len(keys))

			return groups, errors
		}})
}
