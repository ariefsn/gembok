package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ariefsn/gembok/constant"
	"github.com/ariefsn/gembok/env"
	"github.com/ariefsn/gembok/models"
	"github.com/golang-jwt/jwt/v5"
)

type JwtTokenType string

const (
	JwtTokenTypeAccess        JwtTokenType = "access"
	JwtTokenTypeRefresh       JwtTokenType = "refresh"
	JwtTokenTypeResetPassword JwtTokenType = "resetPassword"
)

type JwtClaims struct {
	Id       string
	Email    string
	Type     JwtTokenType
	Provider string
}

type JwtVerificationClaims struct {
	Type string
	Code string
	Id   string
}

func (j JwtClaims) IsAccessToken() bool {
	return j.Type == JwtTokenTypeAccess
}

func (j JwtClaims) IsRefreshToken() bool {
	return j.Type == JwtTokenTypeRefresh
}

type JwtOptions struct {
	Prefix string
}

func JwtGenerate(claims jwt.MapClaims) (string, error) {
	secretKey := env.GetEnv().Jwt.Secret

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return t.SignedString([]byte(secretKey))
}

func JwtVerify[T any](jwtToken string, opts ...JwtOptions) (*T, error) {
	secretKey := env.GetEnv().Jwt.Secret

	tokenString := jwtToken

	if len(opts) > 0 {
		opt := opts[0]

		if opt.Prefix != "" && len(tokenString) > len(opt.Prefix+" ") {
			tokenString = tokenString[len(opt.Prefix+" "):]
		}
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "token contains an invalid number of segments") {
			return nil, errors.New("no credentials found")
		}

		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, err := FromJson[T](token.Claims)
	if err != nil {
		return nil, fmt.Errorf("parse claims failed")
	}

	return &claims, nil
}

func JwtPrefix(jwtToken string) string {
	bearerSplit := strings.Split(jwtToken, " ")
	bearerPrefix := ""

	if len(bearerSplit) > 1 {
		bearerPrefix = bearerSplit[0]
	}

	return bearerPrefix
}

func AccessTokenFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(constant.AccessTokenCtxKey).(string); ok {
		return token
	}

	return ""
}

func RefreshTokenFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(constant.RefreshTokenCtxKey).(string); ok {
		return token
	}

	return ""
}

func JwtClaimsFromContext(ctx context.Context) JwtClaims {
	if claims, ok := ctx.Value(constant.JwtClaimsCtxKey).(JwtClaims); ok {
		return claims
	}

	return JwtClaims{}
}

func JwtIsExpired(token string) (int64, bool) {
	if token == "" {
		return 0, true
	}

	claimsPtr, _ := JwtVerify[models.M](token)
	claims := *claimsPtr
	exp := time.Now().Unix()
	if v, ok := claims["exp"].(float64); ok {
		exp = int64(v)
	}
	expTime := time.Unix(exp, 0)

	if time.Now().After(expTime) {
		return exp, true
	}

	return exp, false
}
