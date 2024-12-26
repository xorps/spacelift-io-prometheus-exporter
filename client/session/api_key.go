package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hasura/go-graphql-client"
)

// FromAPIKey builds a Spacelift session from a combination of endpoint, API key
// ID and API key secret.
func FromAPIKey(ctx context.Context, client *http.Client, endpoint string, keyID string, keySecret Secret) (Session, error) {
	if keySecret == nil {
		return nil, errors.New("keySecret is nil")
	}

	out := &apiKey{
		apiToken: apiToken{
			client:   client,
			endpoint: endpoint,
			timer:    time.Now,
		},
		keyID:     keyID,
		keySecret: keySecret,
	}

	if err := out.exchange(ctx); err != nil {
		return nil, err
	}

	return out, nil
}

type apiKey struct {
	apiToken
	keyID     string
	keySecret Secret
}

func (g *apiKey) BearerToken(ctx context.Context) (string, error) {
	if !g.isFresh() {
		if err := g.exchange(ctx); err != nil {
			return "", err
		}
	}

	return g.apiToken.BearerToken(ctx)
}

func (g *apiKey) RefreshToken(ctx context.Context) error {
	return g.exchange(ctx)
}

func (g *apiKey) exchange(ctx context.Context) error {
	var mutation struct {
		APIKeyUser user `graphql:"apiKeyUser(id: $id, secret: $secret)"`
	}

	secret, err := g.keySecret.read(ctx)
	if err != nil {
		return fmt.Errorf("could not read secret: %w", err)
	}

	variables := map[string]interface{}{
		"id":     graphql.ID(g.keyID),
		"secret": graphql.String(secret),
	}

	if err := g.mutate(ctx, &mutation, variables); err != nil {
		return fmt.Errorf("could not exchange API key and secret for token: %w", err)
	}

	g.setJWT(&mutation.APIKeyUser)

	return nil
}

type Secret interface {
	read(ctx context.Context) (string, error)
}

type InlineSecret struct {
	secret string
}

var _ Secret = (*InlineSecret)(nil)

func NewInlineSecret(secret string) *InlineSecret {
	return &InlineSecret{secret}
}

func (s *InlineSecret) read(_ context.Context) (string, error) {
	return s.secret, nil
}

type FileSecret struct {
	filepath string
}

var _ Secret = (*FileSecret)(nil)

func NewFileSecret(filepath string) *FileSecret {
	return &FileSecret{filepath}
}

func (f *FileSecret) read(_ context.Context) (string, error) {
	// stdlib doesn't support context for File IO -- https://github.com/golang/go/issues/20280
	bytes, err := os.ReadFile(f.filepath)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
