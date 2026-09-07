package authorizer

import "errors"

var (
	// ErrInvalidArgument indicates malformed input supplied to the authorizer.
	ErrInvalidArgument = errors.New("authorizer: invalid argument")
	// ErrNotFound indicates that the requested RBAC object does not exist.
	ErrNotFound = errors.New("authorizer: not found")
	// ErrConflict indicates that an object violates a uniqueness constraint or
	// is still referenced by another object.
	ErrConflict = errors.New("authorizer: conflict")
	// ErrNotMember indicates that a user is not an active member of a tenant.
	ErrNotMember = errors.New("authorizer: user is not a tenant member")
)
