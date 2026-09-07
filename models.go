package authorizer

import "time"

// Status is shared by every object that can be enabled or disabled.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

// User is a global identity. Authentication credentials deliberately do not
// live in this package; the host application remains responsible for login.
type User struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Username    string    `gorm:"size:128;not null;uniqueIndex" json:"username"`
	DisplayName string    `gorm:"size:255" json:"display_name"`
	Email       *string   `gorm:"size:320;uniqueIndex" json:"email,omitempty"`
	Status      Status    `gorm:"size:16;not null;index" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (User) TableName() string { return "authz_users" }

// Tenant is an isolation boundary. Roles and role assignments never cross it.
type Tenant struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Slug      string    `gorm:"size:128;not null;uniqueIndex" json:"slug"`
	Name      string    `gorm:"size:255;not null" json:"name"`
	Status    Status    `gorm:"size:16;not null;index" json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Tenant) TableName() string { return "authz_tenants" }

// Membership connects one user to one tenant.
type Membership struct {
	TenantID  uint64    `gorm:"primaryKey;autoIncrement:false;index:idx_authz_memberships_user" json:"tenant_id"`
	UserID    uint64    `gorm:"primaryKey;autoIncrement:false;index:idx_authz_memberships_user" json:"user_id"`
	Status    Status    `gorm:"size:16;not null;index" json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Tenant Tenant `gorm:"foreignKey:TenantID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	User   User   `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
}

func (Membership) TableName() string { return "authz_memberships" }

// Role is tenant-scoped. Code is unique only inside its tenant.
type Role struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID    uint64    `gorm:"not null;uniqueIndex:idx_authz_roles_tenant_code;index" json:"tenant_id"`
	Code        string    `gorm:"size:128;not null;uniqueIndex:idx_authz_roles_tenant_code" json:"code"`
	Name        string    `gorm:"size:255;not null" json:"name"`
	Description string    `gorm:"size:1024" json:"description"`
	BuiltIn     bool      `gorm:"not null;default:false" json:"built_in"`
	Status      Status    `gorm:"size:16;not null;index" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	Tenant Tenant `gorm:"foreignKey:TenantID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
}

func (Role) TableName() string { return "authz_roles" }

// Permission is global and reusable by roles from every tenant. Code is the
// stable authorization key, for example "invoice.read" or "/api.Invoice/Get".
type Permission struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Code        string    `gorm:"size:255;not null;uniqueIndex" json:"code"`
	Name        string    `gorm:"size:255;not null" json:"name"`
	Description string    `gorm:"size:1024" json:"description"`
	Resource    string    `gorm:"size:128;index" json:"resource"`
	Action      string    `gorm:"size:128;index" json:"action"`
	Status      Status    `gorm:"size:16;not null;index" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (Permission) TableName() string { return "authz_permissions" }

// RolePermission grants a permission to a role.
type RolePermission struct {
	RoleID       uint64    `gorm:"primaryKey;autoIncrement:false" json:"role_id"`
	PermissionID uint64    `gorm:"primaryKey;autoIncrement:false;index" json:"permission_id"`
	CreatedAt    time.Time `json:"created_at"`

	Role       Role       `gorm:"foreignKey:RoleID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	Permission Permission `gorm:"foreignKey:PermissionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
}

func (RolePermission) TableName() string { return "authz_role_permissions" }

// UserRole assigns a tenant role to a tenant member. TenantID is deliberately
// stored in the key so authorization queries are tenant-isolated by construction.
type UserRole struct {
	TenantID  uint64    `gorm:"primaryKey;autoIncrement:false" json:"tenant_id"`
	UserID    uint64    `gorm:"primaryKey;autoIncrement:false;index:idx_authz_user_roles_user" json:"user_id"`
	RoleID    uint64    `gorm:"primaryKey;autoIncrement:false;index" json:"role_id"`
	CreatedAt time.Time `json:"created_at"`

	Tenant Tenant `gorm:"foreignKey:TenantID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	User   User   `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	Role   Role   `gorm:"foreignKey:RoleID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
}

func (UserRole) TableName() string { return "authz_user_roles" }
