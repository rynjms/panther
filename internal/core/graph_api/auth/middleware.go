package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/99designs/gqlgen/graphql"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"io/ioutil"
	"net/http"
)

// The shared context among our resolvers
const userCtxKey = "user"

var (
	// Cognito details
	// FIXME: These need to be dynamic. Currently OSS ones
	awsRegion   = "eu-central-1"
	userPoolId  = "eu-central-1_s68Dw4V9L"
	appClientId = "58amp8dv5rbesqprctgrmc2343"

	// A static list of JSON Web Key Sets that contain the public RSA keys for validating the associated JWTs
	// FIXME: handle error somehow
	keySet, _ = jwk.Fetch(fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsRegion, userPoolId))
)

// Middleware decodes the share session cookie and packs the session into context
// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-2
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// attempt to parse the body of the request
		bodyAsBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		// restore original body bytes for future handlers (next middlewares)
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyAsBytes))

		// get  the actual JSON payload
		var payload graphql.RawParams
		if err := json.Unmarshal(bodyAsBytes, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Check if we did an IntrospectionQuery, in which case we should allow it
		// FIXME: This should be true in DEV environments only since exposing  the entire schema can be a potential
		//  security issue
		if payload.OperationName == "IntrospectionQuery" {
			next.ServeHTTP(w, r)
			return
		}

		// Parse authorization header
		authorizationToken := r.Header.Get("authorization")
		if authorizationToken == "" {
			http.Error(w, "Missing `authorization` header", http.StatusBadRequest)
			return
		}

		// Validate the JWT token. The library validates token expiration automatically for us, so we skip this in our
		// checks below
		jwtParser := jwt.Parser{UseJSONNumber: true}
		claims := CognitoClaims{}
		token, err := jwtParser.ParseWithClaims(authorizationToken, &claims, func(token *jwt.Token) (interface{}, error) {
			// Validating that the algorithm is indeed RSA
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// Making sure that the token specifies a mapping to Cognito's Public Key Sets
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("kid header not found")
			}

			// Making sure that a Public RSA Key exists in the known Key Sets for this particular JWT token
			keys := keySet.LookupKeyID(kid)
			if len(keys) == 0 {
				return nil, fmt.Errorf("Public RSA key %v not found", kid)
			}

			// Return the Public RSA key in a weird format that jwt-go expects
			var raw interface{}
			return raw, keys[0].Raw(&raw)
		})

		if err != nil || !token.Valid {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// put it in context
		ctx := context.WithValue(r.Context(), userCtxKey, token.Claims)

		// and call the next with our new context
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// ForContext finds the user from the context. REQUIRES Middleware to have run.
func ForContext(ctx context.Context) *CognitoClaims {
	return ctx.Value(userCtxKey).(*CognitoClaims)
}
