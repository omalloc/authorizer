# authorizer

一个可直接嵌入 go-kratos v3 项目的多租户 RBAC 模块。数据由 GORM 持久化，HTTP 与 gRPC 共用同一套 Kratos 中间件。

模块只负责授权，不保存密码、不签发 Token。宿主应用负责认证，然后把可信的 `user_id` 和当前 `tenant_id` 交给本模块。

## 安装

```bash
go get github.com/omalloc/authorizer@latest
```

宿主项目还需要自行选择 GORM 数据库驱动，例如 `gorm.io/driver/mysql` 或 `gorm.io/driver/postgres`。

当前基线为 `github.com/go-kratos/kratos/v3 v3.0.0`。JWT 使用 v3 已移出的官方 contrib 模块：

```go
import jwtmw "github.com/go-kratos/kratos/contrib/middleware/jwt/v3"
```

从 Kratos v2 升级时，认证中间件也必须切换到上述 contrib v3 包；v2 JWT 包写入的私有 Context key 无法由 v3 JWT 解析器读取。

## 数据模型

| 表 | 作用 |
| --- | --- |
| `authz_users` | 全局用户身份，不包含认证凭据 |
| `authz_tenants` | 租户隔离边界 |
| `authz_memberships` | 用户与租户的成员关系 |
| `authz_roles` | 租户内角色，`(tenant_id, code)` 唯一 |
| `authz_permissions` | 全局权限定义，`code` 唯一 |
| `authz_user_roles` | 租户内的用户角色分配 |
| `authz_role_permissions` | 角色权限分配 |

用户、租户、成员关系、角色或权限中任意一项被禁用，授权都会立即失效。角色不能跨租户分配。默认匹配精确权限、全局 `*` 和尾部通配符（例如 `invoice.*`）。

## 初始化

```go
db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
    // 建议开启，以便唯一键/外键错误被转换为 authorizer.ErrConflict。
    TranslateError: true,
})
if err != nil {
    return err
}

authz, err := authorizer.New(db)
if err != nil {
    return err
}
if err := authz.AutoMigrate(ctx); err != nil {
    return err
}
```

`AutoMigrate` 会创建七张 `authz_` 前缀表。生产环境也可以用这些公开 model 生成并管理自己的版本化迁移。

`authorizer.Authorizer` 是运行时鉴权接口，只包含 `Enforce` 方法。`authorizer.New` 返回基于 GORM 的 `*authorizer.DefaultAuthorizer`，除实现鉴权接口外，还提供上述迁移能力和后续章节中的用户、租户、角色、权限管理操作。

如果权限数据由其他服务、缓存或自有存储维护，可以实现 `authorizer.Authorizer` 并直接替换默认实现：

```go
type RemoteAuthorizer struct {
    client *PermissionClient
}

func (a *RemoteAuthorizer) Enforce(
    ctx context.Context,
    userID, tenantID uint64,
    permission string,
) (bool, error) {
    return a.client.Check(ctx, userID, tenantID, permission)
}

var authz authorizer.Authorizer = &RemoteAuthorizer{client: permissionClient}

httpServer := http.NewServer(
    http.Middleware(
        authenticationMiddleware,
        rbacmw.Server(authz),
    ),
)
```

自定义实现只负责返回允许、拒绝或检查错误，不需要依赖 GORM，也不需要实现默认实现中的管理操作。

## 扩展 User 字段

Go 不能直接给依赖包中的 `authorizer.User` 增加字段。推荐把 RBAC 用户作为授权身份，将头像、手机号等业务字段放在宿主项目自己的一对一扩展表中。这样升级本包时不会与 `authz_users` 的模型迁移冲突。

```go
type UserProfile struct {
    UserID uint64 `gorm:"primaryKey"`

    Avatar   string `gorm:"size:512"`
    Phone    string `gorm:"size:32;index"`
    Nickname string `gorm:"size:128"`

    User authorizer.User `gorm:"foreignKey:UserID;references:ID"`
}

func (UserProfile) TableName() string {
    return "user_profiles"
}
```

迁移 RBAC 表和业务扩展表：

```go
if err := authz.AutoMigrate(ctx); err != nil {
    return err
}
if err := db.AutoMigrate(&UserProfile{}); err != nil {
    return err
}
```

创建用户及扩展资料时，可以复用同一个 GORM 事务：

```go
err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
    txAuthz, err := authorizer.New(tx)
    if err != nil {
        return err
    }

    user, err := txAuthz.CreateUser(ctx, authorizer.CreateUserInput{
        Username:    "alice",
        DisplayName: "Alice",
    })
    if err != nil {
        return err
    }

    return tx.Create(&UserProfile{
        UserID:   user.ID,
        Avatar:   "https://example.com/avatar.png",
        Phone:    "13800000000",
        Nickname: "Alice",
    }).Error
})
```

通过 GORM 预加载基础用户信息：

```go
var profile UserProfile
err := db.WithContext(ctx).
    Preload("User").
    First(&profile, "user_id = ?", userID).
    Error
```

如果必须把扩展字段放进 `authz_users`，也可以定义指向同一张表的嵌入模型：

```go
type ExtendedUser struct {
    authorizer.User `gorm:"embedded"`

    Avatar string `gorm:"size:512"`
    Phone  string `gorm:"size:32;index"`
}

func (ExtendedUser) TableName() string {
    return "authz_users"
}

if err := db.AutoMigrate(&ExtendedUser{}); err != nil {
    return err
}
```

同表扩展存在以下限制：

- `authorizer.CreateUser` 不会写入新增字段，创建基础用户后需要用宿主项目的 GORM 模型更新。
- `authorizer.UserByID` 只返回基础字段，扩展字段需要通过 `ExtendedUser` 查询。
- 不要修改或重复定义已有列的类型、索引及约束，否则可能与本包后续迁移冲突。

## 创建租户、角色和权限

```go
owner, err := authz.CreateUser(ctx, authorizer.CreateUserInput{
    Username:    "alice",
    DisplayName: "Alice",
})
if err != nil {
    return err
}

// 原子创建租户、成员关系、内置 owner 角色和 * 权限。
tenant, err := authz.CreateTenantWithOwner(ctx, authorizer.CreateTenantInput{
    Slug: "acme",
    Name: "Acme Inc.",
}, owner.ID)
if err != nil {
    return err
}

permissions, err := authz.RegisterPermissions(ctx,
    authorizer.PermissionInput{Code: "invoice.read", Name: "查看发票"},
    authorizer.PermissionInput{Code: "invoice.write", Name: "编辑发票"},
)
if err != nil {
    return err
}

reader, err := authz.CreateRole(ctx, authorizer.CreateRoleInput{
    TenantID: tenant.ID,
    Code:     "invoice_reader",
    Name:     "发票只读",
})
if err != nil {
    return err
}
if err := authz.GrantPermissions(ctx, reader.ID, permissions[0].ID); err != nil {
    return err
}
anotherUser, err := authz.CreateUser(ctx, authorizer.CreateUserInput{Username: "bob"})
if err != nil {
    return err
}
if err := authz.AddMember(ctx, tenant.ID, anotherUser.ID); err != nil {
    return err
}
if err := authz.AssignRoles(ctx, tenant.ID, anotherUser.ID, reader.ID); err != nil {
    return err
}
```

管理操作均接收 `context.Context`。批量注册权限、授权和角色分配是幂等的；租户初始化与移除成员使用事务。

## 接入 Kratos 中间件

默认从 `context.Context` 读取 `authorizer.Principal`，默认权限代码就是 Kratos 的完整 operation。

```go
import (
    "github.com/go-kratos/kratos/v3/transport/http"
    "github.com/omalloc/authorizer"
    rbacmw "github.com/omalloc/authorizer/middleware"
)

// 认证中间件成功后写入身份。tenantID 必须来自已签名 Token、可信网关
// 或服务端校验过的租户选择，不能直接信任用户随意提交的请求头。
ctx = authorizer.WithPrincipal(ctx, authorizer.Principal{
    UserID:   authenticatedUserID,
    TenantID: selectedTenantID,
})

httpServer := http.NewServer(
    http.Middleware(
        authenticationMiddleware,
        rbacmw.Server(authz, rbacmw.WithPermissionMap(map[string]string{
            "/billing.Invoice/Get":    "invoice.read",
            "/billing.Invoice/Update": "invoice.write",
        })),
    ),
)
```

`WithPermissionMap` 中未配置的 operation 仍会被保护，并使用完整 operation 作为权限代码，避免漏配后意外放行。公开接口必须显式声明：

```go
rbacmw.Server(authz, rbacmw.WithPermissionResolver(
    func(ctx context.Context, operation string, request any) (string, bool) {
        if operation == "/grpc.health.v1.Health/Check" {
            return "", false // false 表示公开接口
        }
        return operation, true
    },
))
```

没有身份返回 Kratos `401`，权限不足返回 `403`，数据库或配置错误返回 `500`。

### 读取 Kratos JWT MapClaims

如果认证中间件使用 `jwt.MapClaims`，可直接使用内置解析器。ID 可以是十进制字符串或不超过 JSON 安全整数范围的数字：

```go
rbacmw.Server(authz,
    rbacmw.WithPrincipalResolver(
        rbacmw.JWTMapClaims("user_id", "tenant_id"),
    ),
)
```

自定义 Claims 结构可通过 `WithPrincipalResolver` 自行提取。鉴权中间件必须放在认证中间件之后。

## 不经过中间件直接鉴权

```go
allowed, err := authz.Enforce(ctx, userID, tenantID, "invoice.read")
if err != nil {
    return err
}
if !allowed {
    // 返回宿主应用定义的 permission denied 错误。
}
```

可用 `authorizer.WithPermissionMatcher` 替换默认通配符规则。常用管理接口还包括 `SetUserStatus`、`SetTenantStatus`、`SetMembershipStatus`、`SetRoleStatus`、`SetPermissionStatus`、`RevokeRoles`、`RevokePermissions` 和 `RemoveMember`。

## 测试

```bash
CGO_ENABLED=1 go test ./...
```

仓库测试使用 SQLite 验证完整生命周期、租户隔离、通配符、状态失效、Kratos 401/403 映射和 JWT Claims 解析。
