package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.57

import (
	"context"
	"fmt"
	"time"

	"github.com/ariefsn/gembok/graph"
	"github.com/ariefsn/gembok/models"
)

// PublishedAt is the resolver for the publishedAt field.
func (r *auditResolver) PublishedAt(ctx context.Context, obj *models.Audit) (*time.Time, error) {
	panic(fmt.Errorf("not implemented: PublishedAt - publishedAt"))
}

// PublishedBy is the resolver for the publishedBy field.
func (r *auditResolver) PublishedBy(ctx context.Context, obj *models.Audit) (*string, error) {
	panic(fmt.Errorf("not implemented: PublishedBy - publishedBy"))
}

// Audit returns graph.AuditResolver implementation.
func (r *Resolver) Audit() graph.AuditResolver { return &auditResolver{r} }

// Mutation returns graph.MutationResolver implementation.
func (r *Resolver) Mutation() graph.MutationResolver { return &mutationResolver{r} }

// Query returns graph.QueryResolver implementation.
func (r *Resolver) Query() graph.QueryResolver { return &queryResolver{r} }

type auditResolver struct{ *Resolver }
type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
