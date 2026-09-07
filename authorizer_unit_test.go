package authorizer

import (
	"context"
	"errors"
	"testing"
)

func TestPrincipalContext(t *testing.T) {
	principal := Principal{UserID: 10, TenantID: 20}
	ctx := WithPrincipal(context.Background(), principal)
	actual, ok := PrincipalFromContext(ctx)
	if !ok || actual != principal {
		t.Fatalf("PrincipalFromContext() = %+v, %v", actual, ok)
	}
}

func TestDefaultPermissionMatcher(t *testing.T) {
	tests := []struct {
		granted   string
		requested string
		want      bool
	}{
		{granted: "invoice.read", requested: "invoice.read", want: true},
		{granted: "invoice.*", requested: "invoice.write", want: true},
		{granted: "*", requested: "anything", want: true},
		{granted: "invoice.*", requested: "customer.read", want: false},
	}
	for _, test := range tests {
		if got := matchPermission(test.granted, test.requested); got != test.want {
			t.Errorf("matchPermission(%q, %q) = %v, want %v", test.granted, test.requested, got, test.want)
		}
	}
}

func TestNewRejectsNilDB(t *testing.T) {
	_, err := New(nil)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("New(nil) error = %v", err)
	}
}
