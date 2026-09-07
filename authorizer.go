package authorizer

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// PermissionMatcher decides whether one granted permission satisfies a
// requested permission.
type PermissionMatcher func(granted, requested string) bool

// Option customizes an Authorizer.
type Option func(*Authorizer)

// WithPermissionMatcher replaces the default exact/trailing-wildcard matcher.
func WithPermissionMatcher(matcher PermissionMatcher) Option {
	return func(authorizer *Authorizer) {
		if matcher != nil {
			authorizer.permissionMatcher = matcher
		}
	}
}

// Authorizer owns the persistence and enforcement operations for RBAC.
// It is safe to reuse across requests; *gorm.DB is concurrency-safe.
type Authorizer struct {
	db                *gorm.DB
	permissionMatcher PermissionMatcher
}

// New creates an Authorizer. It does not mutate the schema; call AutoMigrate
// explicitly during application startup.
func New(db *gorm.DB, options ...Option) (*Authorizer, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db is nil", ErrInvalidArgument)
	}
	authorizer := &Authorizer{
		db:                db,
		permissionMatcher: matchPermission,
	}
	for _, option := range options {
		if option != nil {
			option(authorizer)
		}
	}
	return authorizer, nil
}

// DB returns the underlying GORM handle for advanced read-only queries or
// application-managed transactions.
func (a *Authorizer) DB() *gorm.DB { return a.db }

// AutoMigrate creates and evolves all module-owned tables.
func (a *Authorizer) AutoMigrate(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidArgument)
	}
	err := a.db.WithContext(ctx).AutoMigrate(
		&User{},
		&Tenant{},
		&Permission{},
		&Membership{},
		&Role{},
		&RolePermission{},
		&UserRole{},
	)
	if err != nil {
		return fmt.Errorf("authorizer: migrate schema: %w", err)
	}
	return nil
}

// Enforce reports whether an active user, through active roles in an active
// tenant membership, has the requested permission. Missing/inactive subjects
// are denied without exposing which part was missing.
func (a *Authorizer) Enforce(ctx context.Context, userID, tenantID uint64, requested string) (bool, error) {
	if ctx == nil || userID == 0 || tenantID == 0 || strings.TrimSpace(requested) == "" {
		return false, fmt.Errorf("%w: user, tenant and permission are required", ErrInvalidArgument)
	}

	codes, err := a.ListUserPermissionCodes(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	requested = strings.TrimSpace(requested)
	for _, granted := range codes {
		if a.permissionMatcher(granted, requested) {
			return true, nil
		}
	}
	return false, nil
}

// ListUserPermissionCodes returns the effective, distinct permission codes for
// an active user and membership in an active tenant. It returns an empty slice
// when the principal is inactive or has no grants.
func (a *Authorizer) ListUserPermissionCodes(ctx context.Context, userID, tenantID uint64) ([]string, error) {
	if ctx == nil || userID == 0 || tenantID == 0 {
		return nil, fmt.Errorf("%w: user and tenant are required", ErrInvalidArgument)
	}

	var codes []string
	err := a.db.WithContext(ctx).
		Table("authz_permissions AS p").
		Distinct("p.code").
		Joins("JOIN authz_role_permissions AS rp ON rp.permission_id = p.id").
		Joins("JOIN authz_roles AS r ON r.id = rp.role_id").
		Joins("JOIN authz_user_roles AS ur ON ur.role_id = r.id AND ur.tenant_id = r.tenant_id").
		Joins("JOIN authz_memberships AS m ON m.user_id = ur.user_id AND m.tenant_id = ur.tenant_id").
		Joins("JOIN authz_users AS u ON u.id = m.user_id").
		Joins("JOIN authz_tenants AS t ON t.id = m.tenant_id").
		Where("ur.user_id = ? AND ur.tenant_id = ?", userID, tenantID).
		Where(
			"p.status = ? AND r.status = ? AND m.status = ? AND u.status = ? AND t.status = ?",
			StatusActive, StatusActive, StatusActive, StatusActive, StatusActive,
		).
		Order("p.code").
		Pluck("p.code", &codes).Error
	if err != nil {
		return nil, fmt.Errorf("authorizer: list user permissions: %w", err)
	}
	return codes, nil
}

func (a *Authorizer) isActivePrincipal(ctx context.Context, userID, tenantID uint64) (bool, error) {
	var count int64
	err := a.db.WithContext(ctx).
		Table("authz_memberships AS m").
		Joins("JOIN authz_users AS u ON u.id = m.user_id").
		Joins("JOIN authz_tenants AS t ON t.id = m.tenant_id").
		Where("m.user_id = ? AND m.tenant_id = ?", userID, tenantID).
		Where("m.status = ? AND u.status = ? AND t.status = ?", StatusActive, StatusActive, StatusActive).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("authorizer: validate principal: %w", err)
	}
	return count > 0, nil
}

func matchPermission(granted, requested string) bool {
	granted = strings.TrimSpace(granted)
	if granted == "*" || granted == requested {
		return true
	}
	return strings.HasSuffix(granted, "*") &&
		strings.HasPrefix(requested, strings.TrimSuffix(granted, "*"))
}

func validStatus(status Status) bool {
	return status == StatusActive || status == StatusDisabled
}
