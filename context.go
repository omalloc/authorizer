package authorizer

import "context"

// Principal is the authenticated subject plus its selected tenant. A tenant is
// always explicit to prevent accidental cross-tenant authorization.
type Principal struct {
	UserID   uint64
	TenantID uint64
}

type principalContextKey struct{}

// WithPrincipal stores an authenticated principal in a request context.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns a principal previously stored with WithPrincipal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok && principal.UserID != 0 && principal.TenantID != 0
}
