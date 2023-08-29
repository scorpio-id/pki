package transport

import (
	"log"
	"net/http"
	"strings"

	"github.com/scorpio-id/oauth/pkg/oauth"
)

func OAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get JWT from Authorization: Bearer header in request
		// use Verify function from OAuth service (scorpio)
		// if successful, pass on request (optional: add in JWT metadata into request headers)
		// if unsuccssful, return 403 Forbidden and return

		// TODO - review!
		authorization := r.Header.Get("Authorization")
		split := strings.Split(authorization, "Bearer ")
		jwt := split[1]
		if jwt == "" {
			http.Error(w, "jwt must be provided in the Authorization: Bearer header", http.StatusUnauthorized)
			return
		}

		claims, err := oauth.Verify(jwt, "scorpio.io/jwks", http.Client{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// TODO - inspect claims, and add relevant metadata to request headers 
		log.Println(claims)

	})
}
