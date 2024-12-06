package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/ariefsn/gembok/constant"
	"github.com/ariefsn/gembok/env"
)

func Inject(env env.Env) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			// Inject Writer
			ctx := context.WithValue(r.Context(), constant.WriterCtxKey, w)
			r = r.WithContext(ctx)

			// Inject Request
			ctx = context.WithValue(ctx, constant.HttpRequestCtxKey, r)
			r = r.WithContext(ctx)

			// Inject Tokens
			accessToken := r.Header.Get(string(constant.HeaderAuthorization))

			if accessToken != "" {
				splitted := strings.Split(accessToken, " ")
				if len(splitted) > 1 {
					accessToken = splitted[1]
				}
				ctxWithAccessToken := context.WithValue(r.Context(), constant.AccessTokenCtxKey, accessToken)
				r = r.WithContext(ctxWithAccessToken)
			}

			next.ServeHTTP(w, r)
		})
	}
}
