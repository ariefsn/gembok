package resolvers

import "github.com/ariefsn/gembok/models"

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	AuthService models.AuthService
}
