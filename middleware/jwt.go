package middleware

import (
	"context"
	"encoding/json"
	"strconv"

	kratosjwt "github.com/go-kratos/kratos/contrib/middleware/jwt/v3"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/omalloc/authorizer"
)

// JWTMapClaims resolves numeric user and tenant IDs from jwt.MapClaims stored by
// Kratos' JWT authentication middleware. Claims may be JSON numbers or decimal
// strings. Custom claim structs should use WithPrincipalResolver instead.
func JWTMapClaims(userClaim, tenantClaim string) PrincipalResolver {
	return func(ctx context.Context) (authorizer.Principal, bool) {
		claims, ok := kratosjwt.FromContext(ctx)
		if !ok {
			return authorizer.Principal{}, false
		}
		mapClaims, ok := claims.(jwtv5.MapClaims)
		if !ok {
			return authorizer.Principal{}, false
		}
		userID, userOK := claimUint64(mapClaims[userClaim])
		tenantID, tenantOK := claimUint64(mapClaims[tenantClaim])
		if !userOK || !tenantOK || userID == 0 || tenantID == 0 {
			return authorizer.Principal{}, false
		}
		return authorizer.Principal{UserID: userID, TenantID: tenantID}, true
	}
}

func claimUint64(value any) (uint64, bool) {
	const maxSafeJSONInteger = float64(1<<53 - 1)

	switch typed := value.(type) {
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		return parsed, err == nil
	case json.Number:
		parsed, err := strconv.ParseUint(typed.String(), 10, 64)
		return parsed, err == nil
	case float64:
		if typed < 0 || typed > maxSafeJSONInteger || float64(uint64(typed)) != typed {
			return 0, false
		}
		return uint64(typed), true
	case float32:
		converted := float64(typed)
		if converted < 0 || converted > maxSafeJSONInteger || float64(uint64(converted)) != converted {
			return 0, false
		}
		return uint64(converted), true
	case uint64:
		return typed, true
	case uint:
		return uint64(typed), true
	case uint32:
		return uint64(typed), true
	case int:
		return uint64(typed), typed >= 0
	case int64:
		return uint64(typed), typed >= 0
	case int32:
		return uint64(typed), typed >= 0
	default:
		return 0, false
	}
}
