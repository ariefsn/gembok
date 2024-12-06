package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/ariefsn/gembok/constant"
	"github.com/ariefsn/gembok/helper"
	"github.com/ariefsn/gembok/models"
)

func Jwt(authService models.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessToken := r.Header.Get(string(constant.HeaderAuthorization))

			if accessToken == "" {
				helper.ResponseJsonError(w, constant.ResponseStatusRequiredAccessToken, constant.ResponseStatusRequiredAccessToken.String(), http.StatusBadRequest)
				return
			}

			if accessToken != "" {
				splitted := strings.Split(accessToken, " ")
				if len(splitted) > 1 {
					accessToken = splitted[1]
				}

				// Check blacklist
				code, err := authService.CheckBlacklistToken(r.Context())
				if err != nil {
					helper.ResponseJsonError(w, code, err.Error(), http.StatusBadRequest)
					return
				}

				_, err = helper.JwtVerify[helper.JwtClaims](accessToken)
				if err != nil {
					if strings.Contains(err.Error(), "expired") {
						helper.ResponseJsonError(w, constant.ResponseStatusAccessTokenExpired, constant.ResponseStatusAccessTokenExpired.String(), http.StatusBadRequest)
						return
					}
					helper.ResponseJsonError(w, constant.ResponseStatusInvalidAccessToken, constant.ResponseStatusInvalidAccessToken.String(), http.StatusBadRequest)
					return
				}

				claims, err := helper.JwtVerify[helper.JwtClaims](accessToken)
				if err != nil {
					helper.ResponseJsonError(w, constant.ResponseStatusInvalidAccessToken, constant.ResponseStatusInvalidAccessToken.String(), http.StatusBadRequest)
					return
				}

				if !claims.IsAccessToken() {
					helper.ResponseJsonError(w, constant.ResponseStatusInvalidAccessToken, constant.ResponseStatusInvalidAccessToken.String(), http.StatusBadRequest)
					return
				}

				newCtx := context.WithValue(r.Context(), constant.JwtClaimsCtxKey, claims)
				r = r.WithContext(newCtx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
