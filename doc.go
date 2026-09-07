// Package authorizer implements persistent, tenant-isolated role-based access
// control for applications using GORM. Authentication remains the host
// application's responsibility. The middleware subpackage integrates the
// enforcer with go-kratos HTTP and gRPC servers.
package authorizer
