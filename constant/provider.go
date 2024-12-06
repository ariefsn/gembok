package constant

type AuthProvider string

const (
	AuthProviderCredentials AuthProvider = "credentials"
	AuthProviderGithub      AuthProvider = "github"
)

var AuthProviderOauth = map[AuthProvider]bool{
	AuthProviderGithub: true,
}
