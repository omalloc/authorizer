//go:build cgo

package authorizer_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/omalloc/authorizer"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestTenantRBACLifecycleAndIsolation(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := t.Context()

	alice, err := authz.CreateUser(ctx, authorizer.CreateUserInput{Username: "alice"})
	requireNoError(t, err)
	bob, err := authz.CreateUser(ctx, authorizer.CreateUserInput{Username: "bob"})
	requireNoError(t, err)

	acme, err := authz.CreateTenantWithOwner(ctx, authorizer.CreateTenantInput{Slug: "acme", Name: "Acme"}, alice.ID)
	requireNoError(t, err)
	other, err := authz.CreateTenantWithOwner(ctx, authorizer.CreateTenantInput{Slug: "other", Name: "Other"}, bob.ID)
	requireNoError(t, err)

	assertAllowed(t, authz, alice.ID, acme.ID, "anything.at.all", true)
	assertAllowed(t, authz, alice.ID, other.ID, "anything.at.all", false)
	requireNoError(t, authz.AddMember(ctx, other.ID, alice.ID))

	permissions, err := authz.RegisterPermissions(ctx,
		authorizer.PermissionInput{Code: "invoice.read", Name: "Read invoices"},
		authorizer.PermissionInput{Code: "invoice.write", Name: "Write invoices"},
	)
	requireNoError(t, err)
	reader, err := authz.CreateRole(ctx, authorizer.CreateRoleInput{
		TenantID: other.ID,
		Code:     "invoice_reader",
		Name:     "Invoice reader",
	})
	requireNoError(t, err)
	requireNoError(t, authz.GrantPermissions(ctx, reader.ID, permissions[0].ID))
	requireNoError(t, authz.AssignRoles(ctx, other.ID, alice.ID, reader.ID))

	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", true)
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.write", false)
	assertAllowed(t, authz, bob.ID, other.ID, "invoice.write", true)
	assertAllowed(t, authz, alice.ID, acme.ID, "invoice.read", true)

	// A role from a different tenant can never be assigned.
	acmeRoles, err := authz.ListUserRoles(ctx, acme.ID, alice.ID)
	requireNoError(t, err)
	if len(acmeRoles) != 1 {
		t.Fatalf("expected owner role, got %d roles", len(acmeRoles))
	}
	err = authz.AssignRoles(ctx, other.ID, alice.ID, acmeRoles[0].ID)
	if !errors.Is(err, authorizer.ErrInvalidArgument) {
		t.Fatalf("expected cross-tenant role assignment to fail, got %v", err)
	}

	requireNoError(t, authz.SetMembershipStatus(ctx, other.ID, alice.ID, authorizer.StatusDisabled))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", false)
	requireNoError(t, authz.AddMember(ctx, other.ID, alice.ID))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", true)

	requireNoError(t, authz.SetPermissionStatus(ctx, permissions[0].ID, authorizer.StatusDisabled))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", false)
	requireNoError(t, authz.SetPermissionStatus(ctx, permissions[0].ID, authorizer.StatusActive))
	requireNoError(t, authz.SetRoleStatus(ctx, reader.ID, authorizer.StatusDisabled))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", false)
	requireNoError(t, authz.SetRoleStatus(ctx, reader.ID, authorizer.StatusActive))
	requireNoError(t, authz.SetUserStatus(ctx, alice.ID, authorizer.StatusDisabled))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", false)
	requireNoError(t, authz.SetUserStatus(ctx, alice.ID, authorizer.StatusActive))
	requireNoError(t, authz.SetTenantStatus(ctx, other.ID, authorizer.StatusDisabled))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", false)
	requireNoError(t, authz.SetTenantStatus(ctx, other.ID, authorizer.StatusActive))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", true)

	requireNoError(t, authz.RemoveMember(ctx, other.ID, alice.ID))
	assertAllowed(t, authz, alice.ID, other.ID, "invoice.read", false)
}

func TestPermissionRegistrationIsAnUpsert(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := t.Context()

	first, err := authz.RegisterPermissions(ctx, authorizer.PermissionInput{Code: "report.read", Name: "Old"})
	requireNoError(t, err)
	second, err := authz.RegisterPermissions(ctx, authorizer.PermissionInput{Code: "report.read", Name: "New"})
	requireNoError(t, err)
	if second[0].ID != first[0].ID || second[0].Name != "New" {
		t.Fatalf("unexpected upsert result: first=%+v second=%+v", first[0], second[0])
	}
}

func TestTrailingWildcard(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := t.Context()
	user, err := authz.CreateUser(ctx, authorizer.CreateUserInput{Username: "reader"})
	requireNoError(t, err)
	tenant, err := authz.CreateTenant(ctx, authorizer.CreateTenantInput{Slug: "wildcards", Name: "Wildcards"})
	requireNoError(t, err)
	requireNoError(t, authz.AddMember(ctx, tenant.ID, user.ID))
	permission, err := authz.RegisterPermissions(ctx, authorizer.PermissionInput{Code: "document.*"})
	requireNoError(t, err)
	role, err := authz.CreateRole(ctx, authorizer.CreateRoleInput{TenantID: tenant.ID, Code: "docs", Name: "Docs"})
	requireNoError(t, err)
	requireNoError(t, authz.GrantPermissions(ctx, role.ID, permission[0].ID))
	requireNoError(t, authz.AssignRoles(ctx, tenant.ID, user.ID, role.ID))

	assertAllowed(t, authz, user.ID, tenant.ID, "document.read", true)
	assertAllowed(t, authz, user.ID, tenant.ID, "documents.read", false)
}

func newTestAuthorizer(t *testing.T) authorizer.ManagementAuthorizer {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_foreign_keys=on", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	requireNoError(t, err)
	sqlDB, err := db.DB()
	requireNoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	authz, err := authorizer.New(db)
	requireNoError(t, err)
	requireNoError(t, authz.AutoMigrate(t.Context()))
	return authz
}

func assertAllowed(t *testing.T, authz authorizer.Authorizer, userID, tenantID uint64, permission string, expected bool) {
	t.Helper()
	allowed, err := authz.Enforce(t.Context(), userID, tenantID, permission)
	requireNoError(t, err)
	if allowed != expected {
		t.Fatalf("Enforce(%d, %d, %q) = %v, want %v", userID, tenantID, permission, allowed, expected)
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
