package loaders

import (
	"context"
	"net/http"
)

const loadersCtxKey = "dataloaders"

type Loaders struct {
	GroupLoader GroupLoader
}

// Middleware for our loaders. Loaders should be coupled to the request and not shared among multiple ones to avoid caching problems.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loadersCtxKey, &Loaders{
			GroupLoader: GenerateGroupLoader(),
		})
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func For(ctx context.Context) *Loaders {
	return ctx.Value(loadersCtxKey).(*Loaders)
}
