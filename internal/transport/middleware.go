package transport

import (
	"log"
	"net/http"
	"strings"

	"github.com/scorpio-id/oauth/pkg/oauth2"
)

type OAuthMiddleware struct {
	TrustedIssuers []string
}

func (om *OAuthMiddleware) Middleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get JWT from Authorization: Bearer header in request
		// use Verify function from OAuth service (scorpio)
		// if successful, pass on request (optional: add in JWT metadata into request headers)
		// if unsuccssful, return 403 Forbidden and return

		// TODO - review!
		authorization := r.Header.Get("Authorization")
		split := strings.Split(authorization, "Bearer ")
		if len(split) < 2 {
			http.Error(w, "jwt must be provided in the Authorization: Bearer header", http.StatusUnauthorized)
			return
		}

		jwt := split[1]
		if jwt == "" {
			http.Error(w, "jwt must be provided in the Authorization: Bearer header", http.StatusUnauthorized)
			return
		}

		claims, err := oauth2.Verify(jwt, om.TrustedIssuers, http.Client{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// TODO - inspect claims, and add relevant metadata to request headers
		log.Println(claims)

		// continue to originally requested handler
		next.ServeHTTP(w, r)
	})
}
