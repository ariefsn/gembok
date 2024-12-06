package constant

type ContextKey string

const (
	AccessTokenCtxKey  ContextKey = "ACCESS_TOKEN"
	RefreshTokenCtxKey ContextKey = "REFRESH_TOKEN"
	JwtClaimsCtxKey    ContextKey = "JWT_CLAIMS"
	WriterCtxKey       ContextKey = "WRITER"
	HttpRequestCtxKey  ContextKey = "HTTP_REQUEST"
)
