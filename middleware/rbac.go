// Package middleware provides go-kratos server middleware backed by authorizer.
package middleware

import (
	"context"
	"errors"
	"fmt"

	kratoserrors "github.com/go-kratos/kratos/v3/errors"
	kratosmiddleware "github.com/go-kratos/kratos/v3/middleware"
	"github.com/go-kratos/kratos/v3/transport"

	"github.com/omalloc/authorizer"
)

const (
	reasonUnauthenticated = "RBAC_UNAUTHENTICATED"
	reasonDenied          = "RBAC_PERMISSION_DENIED"
	reasonInternal        = "RBAC_INTERNAL_ERROR"
)

// PrincipalResolver extracts the authenticated user and selected tenant.
type PrincipalResolver func(context.Context) (authorizer.Principal, bool)

// PermissionResolver maps a Kratos operation to a permission. Returning false
// explicitly marks the request as public and bypasses authorization.
type PermissionResolver func(ctx context.Context, operation string, request any) (permission string, protected bool)

type config struct {
	principalResolver  PrincipalResolver
	permissionResolver PermissionResolver
}

// Option customizes Server.
type Option func(*config)

// WithPrincipalResolver integrates the middleware with the host application's
// authentication identity. By default authorizer.PrincipalFromContext is used.
func WithPrincipalResolver(resolver PrincipalResolver) Option {
	return func(config *config) {
		if resolver != nil {
			config.principalResolver = resolver
		}
	}
}

// WithPermissionResolver controls route-to-permission mapping. The default uses
// the full Kratos operation string, such as "/billing.Invoice/Get".
func WithPermissionResolver(resolver PermissionResolver) Option {
	return func(config *config) {
		if resolver != nil {
			config.permissionResolver = resolver
		}
	}
}

// WithPermissionMap maps selected operations to domain permission codes. Any
// operation not in the map remains protected using its full operation string.
func WithPermissionMap(permissionByOperation map[string]string) Option {
	permissionMap := make(map[string]string, len(permissionByOperation))
	for operation, permission := range permissionByOperation {
		permissionMap[operation] = permission
	}
	return WithPermissionResolver(func(_ context.Context, operation string, _ any) (string, bool) {
		if permission, exists := permissionMap[operation]; exists {
			return permission, true
		}
		return operation, true
	})
}

// Server builds go-kratos RBAC middleware. Place authentication middleware
// before this middleware so the configured PrincipalResolver can read identity.
func Server(enforcer authorizer.Authorizer, options ...Option) kratosmiddleware.Middleware {
	configuration := config{
		principalResolver: authorizer.PrincipalFromContext,
		permissionResolver: func(_ context.Context, operation string, _ any) (string, bool) {
			return operation, true
		},
	}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}

	return func(next kratosmiddleware.Handler) kratosmiddleware.Handler {
		return func(ctx context.Context, request any) (any, error) {
			if enforcer == nil {
				return nil, kratoserrors.InternalServer(reasonInternal, "RBAC enforcer is not configured")
			}
			transporter, ok := transport.FromServerContext(ctx)
			if !ok || transporter.Operation() == "" {
				return nil, kratoserrors.InternalServer(reasonInternal, "Kratos server operation is unavailable")
			}

			permission, protected := configuration.permissionResolver(ctx, transporter.Operation(), request)
			if !protected {
				return next(ctx, request)
			}
			if permission == "" {
				return nil, kratoserrors.InternalServer(reasonInternal, "RBAC permission mapping is empty")
			}

			principal, ok := configuration.principalResolver(ctx)
			if !ok || principal.UserID == 0 || principal.TenantID == 0 {
				return nil, kratoserrors.Unauthorized(reasonUnauthenticated, "authentication and tenant selection are required")
			}
			allowed, err := enforcer.Enforce(ctx, principal.UserID, principal.TenantID, permission)
			if err != nil {
				if errors.Is(err, authorizer.ErrInvalidArgument) {
					return nil, kratoserrors.InternalServer(reasonInternal, "RBAC configuration is invalid").WithCause(err)
				}
				return nil, kratoserrors.InternalServer(reasonInternal, "RBAC permission check failed").WithCause(err)
			}
			if !allowed {
				return nil, kratoserrors.Forbidden(reasonDenied, fmt.Sprintf("permission %q is required", permission))
			}
			return next(ctx, request)
		}
	}
}
