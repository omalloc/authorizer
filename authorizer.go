package authorizer

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// PermissionMatcher 判断已授予权限是否满足请求权限。
type PermissionMatcher func(granted, requested string) bool

// Authorizer 定义运行时权限判定契约。
// 使用方可以自行实现该接口，并将实现传给 middleware.Server。
type Authorizer interface {
	Enforce(ctx context.Context, userID, tenantID uint64, permission string) (bool, error)
}

// ManagementAuthorizer 定义用户、租户、角色和权限的完整管理契约。
// DefaultAuthorizer 提供基于 GORM 的默认实现；使用方也可以实现该接口，
// 以接入自有存储或权限管理服务。
type ManagementAuthorizer interface {
	Authorizer

	// AddMember 将用户加入租户；已存在的成员关系会被重新激活。
	AddMember(ctx context.Context, tenantID uint64, userID uint64) error
	// AssignRoles 为活跃租户成员幂等分配同一租户内的角色。
	AssignRoles(ctx context.Context, tenantID uint64, userID uint64, roleIDs ...uint64) error
	// AutoMigrate 创建或演进本模块管理的数据库表结构。
	AutoMigrate(ctx context.Context) error
	// CreateRole 在指定租户中创建角色。
	CreateRole(ctx context.Context, input CreateRoleInput) (*Role, error)
	// CreateTenant 创建不包含成员的租户。
	CreateTenant(ctx context.Context, input CreateTenantInput) (*Tenant, error)
	// CreateTenantWithOwner 原子创建租户、所有者成员关系、内置角色及通配权限。
	CreateTenantWithOwner(ctx context.Context, input CreateTenantInput, ownerUserID uint64) (*Tenant, error)
	// CreateUser 创建授权身份，不处理密码等认证凭据。
	CreateUser(ctx context.Context, input CreateUserInput) (*User, error)
	// Enforce 判断指定用户在租户内是否拥有请求权限。
	Enforce(ctx context.Context, userID uint64, tenantID uint64, requested string) (bool, error)
	// GrantPermissions 为角色幂等授予一个或多个权限。
	GrantPermissions(ctx context.Context, roleID uint64, permissionIDs ...uint64) error
	// ListUserPermissionCodes 返回用户在租户内生效且去重后的权限代码。
	ListUserPermissionCodes(ctx context.Context, userID uint64, tenantID uint64) ([]string, error)
	// ListUserRoles 返回用户在指定租户内被分配的角色。
	ListUserRoles(ctx context.Context, tenantID uint64, userID uint64) ([]Role, error)
	// PermissionByCode 根据稳定权限代码查询权限。
	PermissionByCode(ctx context.Context, code string) (*Permission, error)
	// RegisterPermissions 根据权限代码幂等注册或更新权限。
	RegisterPermissions(ctx context.Context, inputs ...PermissionInput) ([]Permission, error)
	// RemoveMember 原子删除租户成员关系及其在该租户内的角色分配。
	RemoveMember(ctx context.Context, tenantID uint64, userID uint64) error
	// RevokePermissions 撤销角色的一个或多个权限。
	RevokePermissions(ctx context.Context, roleID uint64, permissionIDs ...uint64) error
	// RevokeRoles 撤销用户在指定租户内的一个或多个角色。
	RevokeRoles(ctx context.Context, tenantID uint64, userID uint64, roleIDs ...uint64) error
	// RoleByID 根据主键查询角色。
	RoleByID(ctx context.Context, roleID uint64) (*Role, error)
	// SetMembershipStatus 启用或停用成员关系，并保留已有角色分配。
	SetMembershipStatus(ctx context.Context, tenantID uint64, userID uint64, status Status) error
	// SetPermissionStatus 启用或停用权限。
	SetPermissionStatus(ctx context.Context, permissionID uint64, status Status) error
	// SetRoleStatus 启用或停用角色。
	SetRoleStatus(ctx context.Context, roleID uint64, status Status) error
	// SetTenantStatus 启用或停用租户。
	SetTenantStatus(ctx context.Context, tenantID uint64, status Status) error
	// SetUserStatus 全局启用或停用用户。
	SetUserStatus(ctx context.Context, userID uint64, status Status) error
	// TenantByID 根据主键查询租户。
	TenantByID(ctx context.Context, tenantID uint64) (*Tenant, error)
	// UserByID 根据主键查询用户。
	UserByID(ctx context.Context, userID uint64) (*User, error)
	// UserByUsername 根据稳定用户名查询用户。
	UserByUsername(ctx context.Context, username string) (*User, error)
}

// Option 配置 DefaultAuthorizer。
type Option func(*DefaultAuthorizer)

// WithPermissionMatcher replaces the default exact/trailing-wildcard matcher.
func WithPermissionMatcher(matcher PermissionMatcher) Option {
	return func(authorizer *DefaultAuthorizer) {
		if matcher != nil {
			authorizer.permissionMatcher = matcher
		}
	}
}

// DefaultAuthorizer 是基于 GORM 的默认 RBAC 实现。
// 它可在请求之间安全复用，因为 *gorm.DB 支持并发使用。
type DefaultAuthorizer struct {
	db                *gorm.DB
	permissionMatcher PermissionMatcher
}

var _ Authorizer = (*DefaultAuthorizer)(nil)

// New 创建基于 GORM 的默认实现。它不会修改数据库结构；
// 应用启动时需要显式调用 AutoMigrate。
func New(db *gorm.DB, options ...Option) (ManagementAuthorizer, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db is nil", ErrInvalidArgument)
	}
	authorizer := &DefaultAuthorizer{
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
func (a *DefaultAuthorizer) DB() *gorm.DB { return a.db }

// AutoMigrate creates and evolves all module-owned tables.
func (a *DefaultAuthorizer) AutoMigrate(ctx context.Context) error {
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
func (a *DefaultAuthorizer) Enforce(ctx context.Context, userID, tenantID uint64, requested string) (bool, error) {
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
func (a *DefaultAuthorizer) ListUserPermissionCodes(ctx context.Context, userID, tenantID uint64) ([]string, error) {
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

func (a *DefaultAuthorizer) isActivePrincipal(ctx context.Context, userID, tenantID uint64) (bool, error) {
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
