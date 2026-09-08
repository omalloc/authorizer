package authorizer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type CreateUserInput struct {
	Username    string
	DisplayName string
	Email       *string
}

type CreateTenantInput struct {
	Slug string
	Name string
}

type CreateRoleInput struct {
	TenantID    uint64
	Code        string
	Name        string
	Description string
	BuiltIn     bool
}

type PermissionInput struct {
	Code        string
	Name        string
	Description string
	Resource    string
	Action      string
}

// CreateUser registers an authorization identity. Passwords and other
// credentials belong to the host application's authentication subsystem.
func (a *DefaultAuthorizer) CreateUser(ctx context.Context, input CreateUserInput) (*User, error) {
	username := strings.TrimSpace(input.Username)
	if ctx == nil || username == "" {
		return nil, fmt.Errorf("%w: username is required", ErrInvalidArgument)
	}
	if len(username) > 128 {
		return nil, fmt.Errorf("%w: username exceeds 128 bytes", ErrInvalidArgument)
	}
	displayName := strings.TrimSpace(input.DisplayName)
	email := normalizeEmail(input.Email)
	if len(displayName) > 255 || (email != nil && len(*email) > 320) {
		return nil, fmt.Errorf("%w: display name or email is too long", ErrInvalidArgument)
	}

	user := &User{
		Username:    username,
		DisplayName: displayName,
		Email:       email,
		Status:      StatusActive,
	}
	if err := a.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, writeError("create user", err)
	}
	return user, nil
}

// UserByID fetches a user by primary key.
func (a *DefaultAuthorizer) UserByID(ctx context.Context, userID uint64) (*User, error) {
	if ctx == nil || userID == 0 {
		return nil, fmt.Errorf("%w: user is required", ErrInvalidArgument)
	}
	var user User
	if err := a.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, readError("get user", err)
	}
	return &user, nil
}

// UserByUsername fetches a user by its stable username.
func (a *DefaultAuthorizer) UserByUsername(ctx context.Context, username string) (*User, error) {
	username = strings.TrimSpace(username)
	if ctx == nil || username == "" {
		return nil, fmt.Errorf("%w: username is required", ErrInvalidArgument)
	}
	var user User
	if err := a.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, readError("get user", err)
	}
	return &user, nil
}

// SetUserStatus enables or disables a user globally.
func (a *DefaultAuthorizer) SetUserStatus(ctx context.Context, userID uint64, status Status) error {
	if ctx == nil || userID == 0 || !validStatus(status) {
		return fmt.Errorf("%w: user and valid status are required", ErrInvalidArgument)
	}
	return updateStatus(a.db.WithContext(ctx), &User{}, status, "set user status", "id = ?", userID)
}

// CreateTenant creates an empty tenant.
func (a *DefaultAuthorizer) CreateTenant(ctx context.Context, input CreateTenantInput) (*Tenant, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", ErrInvalidArgument)
	}
	return createTenant(a.db.WithContext(ctx), ctx, input)
}

// CreateTenantWithOwner atomically creates a tenant, activates owner membership,
// creates a built-in owner role with "*", and assigns that role to ownerUserID.
func (a *DefaultAuthorizer) CreateTenantWithOwner(ctx context.Context, input CreateTenantInput, ownerUserID uint64) (*Tenant, error) {
	if ctx == nil || ownerUserID == 0 {
		return nil, fmt.Errorf("%w: owner is required", ErrInvalidArgument)
	}
	var tenant *Tenant
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var owner User
		if err := tx.Where("id = ? AND status = ?", ownerUserID, StatusActive).First(&owner).Error; err != nil {
			return readError("get tenant owner", err)
		}

		var err error
		tenant, err = createTenant(tx, ctx, input)
		if err != nil {
			return err
		}
		txAuthorizer := &DefaultAuthorizer{db: tx, permissionMatcher: a.permissionMatcher}
		if err := txAuthorizer.AddMember(ctx, tenant.ID, ownerUserID); err != nil {
			return err
		}
		permissions, err := txAuthorizer.RegisterPermissions(ctx, PermissionInput{
			Code:        "*",
			Name:        "All permissions",
			Description: "Built-in tenant owner wildcard permission",
		})
		if err != nil {
			return err
		}
		role, err := txAuthorizer.CreateRole(ctx, CreateRoleInput{
			TenantID:    tenant.ID,
			Code:        "owner",
			Name:        "Owner",
			Description: "Built-in tenant owner role",
			BuiltIn:     true,
		})
		if err != nil {
			return err
		}
		if err := txAuthorizer.GrantPermissions(ctx, role.ID, permissions[0].ID); err != nil {
			return err
		}
		return txAuthorizer.AssignRoles(ctx, tenant.ID, ownerUserID, role.ID)
	})
	if err != nil {
		return nil, err
	}
	return tenant, nil
}

func createTenant(db *gorm.DB, ctx context.Context, input CreateTenantInput) (*Tenant, error) {
	slug, name := strings.TrimSpace(input.Slug), strings.TrimSpace(input.Name)
	if ctx == nil || slug == "" || name == "" {
		return nil, fmt.Errorf("%w: tenant slug and name are required", ErrInvalidArgument)
	}
	if len(slug) > 128 || len(name) > 255 {
		return nil, fmt.Errorf("%w: tenant slug or name is too long", ErrInvalidArgument)
	}
	tenant := &Tenant{Slug: slug, Name: name, Status: StatusActive}
	if err := db.Create(tenant).Error; err != nil {
		return nil, writeError("create tenant", err)
	}
	return tenant, nil
}

func (a *DefaultAuthorizer) TenantByID(ctx context.Context, tenantID uint64) (*Tenant, error) {
	if ctx == nil || tenantID == 0 {
		return nil, fmt.Errorf("%w: tenant is required", ErrInvalidArgument)
	}
	var tenant Tenant
	if err := a.db.WithContext(ctx).First(&tenant, tenantID).Error; err != nil {
		return nil, readError("get tenant", err)
	}
	return &tenant, nil
}

func (a *DefaultAuthorizer) SetTenantStatus(ctx context.Context, tenantID uint64, status Status) error {
	if ctx == nil || tenantID == 0 || !validStatus(status) {
		return fmt.Errorf("%w: tenant and valid status are required", ErrInvalidArgument)
	}
	return updateStatus(a.db.WithContext(ctx), &Tenant{}, status, "set tenant status", "id = ?", tenantID)
}

// AddMember adds or reactivates a user in a tenant.
func (a *DefaultAuthorizer) AddMember(ctx context.Context, tenantID, userID uint64) error {
	if ctx == nil || tenantID == 0 || userID == 0 {
		return fmt.Errorf("%w: user and tenant are required", ErrInvalidArgument)
	}
	if err := a.requireActiveUserAndTenant(ctx, tenantID, userID); err != nil {
		return err
	}
	membership := Membership{TenantID: tenantID, UserID: userID, Status: StatusActive}
	err := a.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "updated_at"}),
	}).Create(&membership).Error
	if err != nil {
		return writeError("add tenant member", err)
	}
	return nil
}

// SetMembershipStatus enables or disables one tenant membership. Existing role
// assignments are retained, allowing safe suspension and restoration.
func (a *DefaultAuthorizer) SetMembershipStatus(ctx context.Context, tenantID, userID uint64, status Status) error {
	if ctx == nil || tenantID == 0 || userID == 0 || !validStatus(status) {
		return fmt.Errorf("%w: user, tenant and valid status are required", ErrInvalidArgument)
	}
	return updateStatus(
		a.db.WithContext(ctx),
		&Membership{},
		status,
		"set membership status",
		"tenant_id = ? AND user_id = ?",
		tenantID,
		userID,
	)
}

// RemoveMember atomically deletes a membership and all of that user's role
// assignments in the tenant.
func (a *DefaultAuthorizer) RemoveMember(ctx context.Context, tenantID, userID uint64) error {
	if ctx == nil || tenantID == 0 || userID == 0 {
		return fmt.Errorf("%w: user and tenant are required", ErrInvalidArgument)
	}
	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&UserRole{}).Error; err != nil {
			return writeError("remove member roles", err)
		}
		result := tx.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&Membership{})
		if result.Error != nil {
			return writeError("remove tenant member", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%w: membership", ErrNotFound)
		}
		return nil
	})
}

// CreateRole creates a tenant-scoped role.
func (a *DefaultAuthorizer) CreateRole(ctx context.Context, input CreateRoleInput) (*Role, error) {
	code, name := strings.TrimSpace(input.Code), strings.TrimSpace(input.Name)
	if ctx == nil || input.TenantID == 0 || code == "" || name == "" {
		return nil, fmt.Errorf("%w: tenant, role code and name are required", ErrInvalidArgument)
	}
	if len(code) > 128 || len(name) > 255 {
		return nil, fmt.Errorf("%w: role code or name is too long", ErrInvalidArgument)
	}
	description := strings.TrimSpace(input.Description)
	if len(description) > 1024 {
		return nil, fmt.Errorf("%w: role description is too long", ErrInvalidArgument)
	}
	if err := a.requireActiveTenant(ctx, input.TenantID); err != nil {
		return nil, err
	}
	role := &Role{
		TenantID:    input.TenantID,
		Code:        code,
		Name:        name,
		Description: description,
		BuiltIn:     input.BuiltIn,
		Status:      StatusActive,
	}
	if err := a.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, writeError("create role", err)
	}
	return role, nil
}

func (a *DefaultAuthorizer) RoleByID(ctx context.Context, roleID uint64) (*Role, error) {
	if ctx == nil || roleID == 0 {
		return nil, fmt.Errorf("%w: role is required", ErrInvalidArgument)
	}
	var role Role
	if err := a.db.WithContext(ctx).First(&role, roleID).Error; err != nil {
		return nil, readError("get role", err)
	}
	return &role, nil
}

func (a *DefaultAuthorizer) SetRoleStatus(ctx context.Context, roleID uint64, status Status) error {
	if ctx == nil || roleID == 0 || !validStatus(status) {
		return fmt.Errorf("%w: role and valid status are required", ErrInvalidArgument)
	}
	return updateStatus(a.db.WithContext(ctx), &Role{}, status, "set role status", "id = ?", roleID)
}

// RegisterPermissions inserts or updates permissions by code and returns them
// in the same order as the inputs.
func (a *DefaultAuthorizer) RegisterPermissions(ctx context.Context, inputs ...PermissionInput) ([]Permission, error) {
	if ctx == nil || len(inputs) == 0 {
		return nil, fmt.Errorf("%w: at least one permission is required", ErrInvalidArgument)
	}
	permissions := make([]Permission, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		code := strings.TrimSpace(input.Code)
		if code == "" || len(code) > 255 {
			return nil, fmt.Errorf("%w: permission code is required and limited to 255 bytes", ErrInvalidArgument)
		}
		if _, exists := seen[code]; exists {
			return nil, fmt.Errorf("%w: duplicate permission code %q", ErrInvalidArgument, code)
		}
		seen[code] = struct{}{}
		name := strings.TrimSpace(input.Name)
		if name == "" {
			name = code
		}
		description := strings.TrimSpace(input.Description)
		resource := strings.TrimSpace(input.Resource)
		action := strings.TrimSpace(input.Action)
		if len(name) > 255 || len(description) > 1024 || len(resource) > 128 || len(action) > 128 {
			return nil, fmt.Errorf("%w: permission metadata is too long", ErrInvalidArgument)
		}
		permissions = append(permissions, Permission{
			Code:        code,
			Name:        name,
			Description: description,
			Resource:    resource,
			Action:      action,
			Status:      StatusActive,
		})
	}

	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for index := range permissions {
			permission := &permissions[index]
			err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "code"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"name", "description", "resource", "action", "status", "updated_at",
				}),
			}).Create(permission).Error
			if err != nil {
				return writeError("register permission", err)
			}
			var stored Permission
			if err := tx.Where("code = ?", permission.Code).First(&stored).Error; err != nil {
				return readError("reload permission", err)
			}
			permissions[index] = stored
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

func (a *DefaultAuthorizer) PermissionByCode(ctx context.Context, code string) (*Permission, error) {
	code = strings.TrimSpace(code)
	if ctx == nil || code == "" {
		return nil, fmt.Errorf("%w: permission code is required", ErrInvalidArgument)
	}
	var permission Permission
	if err := a.db.WithContext(ctx).Where("code = ?", code).First(&permission).Error; err != nil {
		return nil, readError("get permission", err)
	}
	return &permission, nil
}

func (a *DefaultAuthorizer) SetPermissionStatus(ctx context.Context, permissionID uint64, status Status) error {
	if ctx == nil || permissionID == 0 || !validStatus(status) {
		return fmt.Errorf("%w: permission and valid status are required", ErrInvalidArgument)
	}
	return updateStatus(a.db.WithContext(ctx), &Permission{}, status, "set permission status", "id = ?", permissionID)
}

// GrantPermissions idempotently grants permissions to a role.
func (a *DefaultAuthorizer) GrantPermissions(ctx context.Context, roleID uint64, permissionIDs ...uint64) error {
	permissionIDs = uniqueIDs(permissionIDs)
	if ctx == nil || roleID == 0 || len(permissionIDs) == 0 {
		return fmt.Errorf("%w: role and permissions are required", ErrInvalidArgument)
	}
	if err := a.requireRoleAndPermissions(ctx, roleID, permissionIDs); err != nil {
		return err
	}
	rows := make([]RolePermission, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		rows = append(rows, RolePermission{RoleID: roleID, PermissionID: permissionID})
	}
	if err := a.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error; err != nil {
		return writeError("grant role permissions", err)
	}
	return nil
}

func (a *DefaultAuthorizer) RevokePermissions(ctx context.Context, roleID uint64, permissionIDs ...uint64) error {
	permissionIDs = uniqueIDs(permissionIDs)
	if ctx == nil || roleID == 0 || len(permissionIDs) == 0 {
		return fmt.Errorf("%w: role and permissions are required", ErrInvalidArgument)
	}
	err := a.db.WithContext(ctx).
		Where("role_id = ? AND permission_id IN ?", roleID, permissionIDs).
		Delete(&RolePermission{}).Error
	if err != nil {
		return writeError("revoke role permissions", err)
	}
	return nil
}

// AssignRoles idempotently assigns tenant roles to an active tenant member.
func (a *DefaultAuthorizer) AssignRoles(ctx context.Context, tenantID, userID uint64, roleIDs ...uint64) error {
	roleIDs = uniqueIDs(roleIDs)
	if ctx == nil || tenantID == 0 || userID == 0 || len(roleIDs) == 0 {
		return fmt.Errorf("%w: tenant, user and roles are required", ErrInvalidArgument)
	}
	active, err := a.isActivePrincipal(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	if !active {
		return ErrNotMember
	}
	var count int64
	if err := a.db.WithContext(ctx).Model(&Role{}).
		Where("tenant_id = ? AND id IN ? AND status = ?", tenantID, roleIDs, StatusActive).
		Count(&count).Error; err != nil {
		return fmt.Errorf("authorizer: validate roles: %w", err)
	}
	if count != int64(len(roleIDs)) {
		return fmt.Errorf("%w: role is missing, disabled, or belongs to another tenant", ErrInvalidArgument)
	}
	rows := make([]UserRole, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		rows = append(rows, UserRole{TenantID: tenantID, UserID: userID, RoleID: roleID})
	}
	if err := a.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error; err != nil {
		return writeError("assign user roles", err)
	}
	return nil
}

func (a *DefaultAuthorizer) RevokeRoles(ctx context.Context, tenantID, userID uint64, roleIDs ...uint64) error {
	roleIDs = uniqueIDs(roleIDs)
	if ctx == nil || tenantID == 0 || userID == 0 || len(roleIDs) == 0 {
		return fmt.Errorf("%w: tenant, user and roles are required", ErrInvalidArgument)
	}
	err := a.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND role_id IN ?", tenantID, userID, roleIDs).
		Delete(&UserRole{}).Error
	if err != nil {
		return writeError("revoke user roles", err)
	}
	return nil
}

func (a *DefaultAuthorizer) ListUserRoles(ctx context.Context, tenantID, userID uint64) ([]Role, error) {
	if ctx == nil || tenantID == 0 || userID == 0 {
		return nil, fmt.Errorf("%w: tenant and user are required", ErrInvalidArgument)
	}
	var roles []Role
	err := a.db.WithContext(ctx).
		Table("authz_roles AS r").
		Joins("JOIN authz_user_roles AS ur ON ur.role_id = r.id AND ur.tenant_id = r.tenant_id").
		Where("ur.tenant_id = ? AND ur.user_id = ?", tenantID, userID).
		Order("r.code").
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("authorizer: list user roles: %w", err)
	}
	return roles, nil
}

func (a *DefaultAuthorizer) requireActiveUserAndTenant(ctx context.Context, tenantID, userID uint64) error {
	var users int64
	if err := a.db.WithContext(ctx).Model(&User{}).Where("id = ? AND status = ?", userID, StatusActive).Count(&users).Error; err != nil {
		return fmt.Errorf("authorizer: validate user: %w", err)
	}
	if users == 0 {
		return fmt.Errorf("%w: active user", ErrNotFound)
	}
	return a.requireActiveTenant(ctx, tenantID)
}

func (a *DefaultAuthorizer) requireActiveTenant(ctx context.Context, tenantID uint64) error {
	var tenants int64
	if err := a.db.WithContext(ctx).Model(&Tenant{}).Where("id = ? AND status = ?", tenantID, StatusActive).Count(&tenants).Error; err != nil {
		return fmt.Errorf("authorizer: validate tenant: %w", err)
	}
	if tenants == 0 {
		return fmt.Errorf("%w: active tenant", ErrNotFound)
	}
	return nil
}

func (a *DefaultAuthorizer) requireRoleAndPermissions(ctx context.Context, roleID uint64, permissionIDs []uint64) error {
	var roles int64
	if err := a.db.WithContext(ctx).Model(&Role{}).Where("id = ?", roleID).Count(&roles).Error; err != nil {
		return fmt.Errorf("authorizer: validate role: %w", err)
	}
	if roles == 0 {
		return fmt.Errorf("%w: role", ErrNotFound)
	}
	var permissions int64
	if err := a.db.WithContext(ctx).Model(&Permission{}).Where("id IN ?", permissionIDs).Count(&permissions).Error; err != nil {
		return fmt.Errorf("authorizer: validate permissions: %w", err)
	}
	if permissions != int64(len(permissionIDs)) {
		return fmt.Errorf("%w: one or more permissions", ErrNotFound)
	}
	return nil
}

func updateStatus(db *gorm.DB, model any, status Status, operation, condition string, args ...any) error {
	var count int64
	if err := db.Model(model).Where(condition, args...).Count(&count).Error; err != nil {
		return fmt.Errorf("authorizer: %s: %w", operation, err)
	}
	if count == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, operation)
	}
	result := db.Model(model).Where(condition, args...).Update("status", status)
	if result.Error != nil {
		return writeError(operation, result.Error)
	}
	return nil
}

func uniqueIDs(ids []uint64) []uint64 {
	result := make([]uint64, 0, len(ids))
	seen := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func normalizeEmail(email *string) *string {
	if email == nil {
		return nil
	}
	normalized := strings.TrimSpace(*email)
	if normalized == "" {
		return nil
	}
	return &normalized
}

func readError(operation string, err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("%w: %s", ErrNotFound, operation)
	}
	return fmt.Errorf("authorizer: %s: %w", operation, err)
}

func writeError(operation string, err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) || errors.Is(err, gorm.ErrForeignKeyViolated) {
		return fmt.Errorf("%w: %s: %v", ErrConflict, operation, err)
	}
	return fmt.Errorf("authorizer: %s: %w", operation, err)
}
