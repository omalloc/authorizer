# Repository Guidelines

## Project Structure & Module Organization

This Go module (`github.com/omalloc/authorizer`) provides tenant-isolated RBAC. Core code lives in the root: `authorizer.go` handles enforcement, `management.go` contains management operations, `models.go` defines GORM models, and `context.go` carries request principals. The `middleware/` package integrates JWT claims and authorization with go-kratos.

Tests sit beside their code. Root `*_test.go` files exercise the API and RBAC lifecycle; `middleware/rbac_test.go` covers middleware behavior.

## Build, Test, and Development Commands

- `go build ./...` compiles every package.
- `go test ./...` runs tests. The SQLite lifecycle suite requires CGO and a C toolchain.
- `go test -race ./...` checks concurrent use for data races.
- `go test -cover ./...` reports coverage; no threshold is configured.
- `go vet ./...` performs standard static analysis.
- `gofmt -w .` formats all Go sources before review.

Run commands from the module root. Use `go mod tidy` when imports change and commit resulting module-file updates.

## Coding Style & Naming Conventions

Follow idiomatic Go and let `gofmt` determine layout. Use lowercase package names, `PascalCase` for exported identifiers, `camelCase` for unexported identifiers, and `ErrName` for sentinel errors. Document public APIs with comments beginning with the declared name. Wrap errors with `%w`. Write new source-code comments in Chinese.

## Testing Guidelines

Use the standard `testing` package and name tests `TestBehavior`, such as `TestTenantRBACLifecycleAndIsolation`. Prefer table-driven tests and `t.Helper()` assertions. Authorization changes should cover tenant isolation, disabled entities, invalid input, and allowed and denied paths. Middleware tests should verify status codes and handler execution.

## Commit & Pull Request Guidelines

History currently contains only `first commit`, so no established message convention exists. Use concise, imperative subjects such as `Add role deletion validation`, and keep unrelated changes separate. Pull requests should explain the behavior change, compatibility or migration impact, and commands run. Link relevant issues; include screenshots only when documentation rendering or other visual output changes.

## Security & Configuration Tips

Treat `user_id` and `tenant_id` as trusted only when supplied by signed claims, a trusted gateway, or server-side validation. This module authorizes requests; it does not authenticate users, store passwords, or issue tokens. Avoid weakening the default-deny behavior when adding public operations.
