package middleware

import (
	"context"
	"testing"

	kratosjwt "github.com/go-kratos/kratos/contrib/middleware/jwt/v3"
	kratoserrors "github.com/go-kratos/kratos/v3/errors"
	"github.com/go-kratos/kratos/v3/transport"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/omalloc/authorizer"
)

type enforcerStub struct {
	permission string
	allowed    bool
	err        error
}

func (stub *enforcerStub) Enforce(_ context.Context, _, _ uint64, permission string) (bool, error) {
	stub.permission = permission
	return stub.allowed, stub.err
}

func TestServerAllowsMappedPermission(t *testing.T) {
	enforcer := &enforcerStub{allowed: true}
	middleware := Server(enforcer, WithPermissionMap(map[string]string{
		"/invoice.Invoice/Get": "invoice.read",
	}))
	called := false
	handler := middleware(func(_ context.Context, _ any) (any, error) {
		called = true
		return "ok", nil
	})
	ctx := serverContext("/invoice.Invoice/Get")
	ctx = authorizer.WithPrincipal(ctx, authorizer.Principal{UserID: 7, TenantID: 9})

	reply, err := handler(ctx, nil)
	if err != nil || reply != "ok" || !called {
		t.Fatalf("expected handler success, reply=%v called=%v err=%v", reply, called, err)
	}
	if enforcer.permission != "invoice.read" {
		t.Fatalf("mapped permission = %q", enforcer.permission)
	}
}

func TestServerRejectsMissingIdentityAndDeniedPermission(t *testing.T) {
	enforcer := &enforcerStub{allowed: false}
	handler := Server(enforcer)(func(_ context.Context, _ any) (any, error) { return "unexpected", nil })

	_, err := handler(serverContext("/invoice.Invoice/Get"), nil)
	if kratoserrors.Code(err) != 401 {
		t.Fatalf("missing identity code = %d, want 401; err=%v", kratoserrors.Code(err), err)
	}

	ctx := authorizer.WithPrincipal(serverContext("/invoice.Invoice/Get"), authorizer.Principal{UserID: 7, TenantID: 9})
	_, err = handler(ctx, nil)
	if kratoserrors.Code(err) != 403 {
		t.Fatalf("denied code = %d, want 403; err=%v", kratoserrors.Code(err), err)
	}
}

func TestServerCanExplicitlySkipPublicOperation(t *testing.T) {
	handler := Server(&enforcerStub{}, WithPermissionResolver(
		func(_ context.Context, operation string, _ any) (string, bool) {
			return "", operation != "/health.Check/Live"
		},
	))(func(_ context.Context, _ any) (any, error) { return "healthy", nil })

	reply, err := handler(serverContext("/health.Check/Live"), nil)
	if err != nil || reply != "healthy" {
		t.Fatalf("public operation failed: reply=%v err=%v", reply, err)
	}
}

func TestJWTMapClaims(t *testing.T) {
	ctx := kratosjwt.NewContext(context.Background(), jwtv5.MapClaims{
		"user_id":   "42",
		"tenant_id": float64(11),
	})
	principal, ok := JWTMapClaims("user_id", "tenant_id")(ctx)
	if !ok || principal.UserID != 42 || principal.TenantID != 11 {
		t.Fatalf("unexpected principal: %+v, ok=%v", principal, ok)
	}
}

type fakeTransport struct {
	operation string
	header    memoryHeader
}

func (fake *fakeTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (fake *fakeTransport) Endpoint() string                { return "http://localhost" }
func (fake *fakeTransport) Operation() string               { return fake.operation }
func (fake *fakeTransport) RequestHeader() transport.Header { return fake.header }
func (fake *fakeTransport) ReplyHeader() transport.Header   { return fake.header }

type memoryHeader map[string][]string

func (header memoryHeader) Get(key string) string {
	values := header[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (header memoryHeader) Set(key, value string) { header[key] = []string{value} }
func (header memoryHeader) Add(key, value string) { header[key] = append(header[key], value) }
func (header memoryHeader) Keys() []string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	return keys
}
func (header memoryHeader) Values(key string) []string { return header[key] }

func serverContext(operation string) context.Context {
	return transport.NewServerContext(context.Background(), &fakeTransport{
		operation: operation,
		header:    make(memoryHeader),
	})
}
