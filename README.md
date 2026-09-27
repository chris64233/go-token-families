# go-token-families

刷新令牌家族（Refresh Token Family）轮换与重放检测的 Go 实现。

开发环境：Go 1.23.0。

## 核心概念

- **令牌家族（Family）**：每次登录创建一个家族，家族内的刷新令牌按代（generation）轮换。
- **轮换（Rotation）**：每次刷新成功后，当前刷新令牌立即一次性失效，同时签发下一代访问令牌与刷新令牌。
- **重放检测（Replay Detection）**：已被消费的旧刷新令牌若被另一个请求再次使用，视为重放，整个家族立即被撤销。
- **幂等重试（Idempotency）**：网络重试场景下，携带相同幂等键的相同刷新请求可在有限窗口内取回与首次完全相同的结果。

## 安全设计

- **只存摘要**：持久化层只保存令牌的 SHA-256 摘要，明文令牌仅存在于接口返回值中。
- **幂等结果可复现**：携带幂等键的请求，其下一代令牌由服务端密钥经 HMAC-SHA256 确定性派生
  （`HMAC(secret, kind|familyID|generation|idempotencyKey)`），因此窗口内重试可以重算出相同结果，
  而存储层依然只保存摘要，无需为幂等缓存明文。生产环境必须传入稳定的高熵密钥。
- **统一时钟**：过期时间与幂等重试窗口统一使用注入的 `Clock` 判断，测试可用 `ManualClock` 精确控制。
- **日志脱敏**：错误信息与审计事件（`AuditEvent`）只包含家族 ID、用户 ID、代数、原因等非敏感字段，
  绝不包含令牌明文或摘要。

## 并发与一致性语义

所有状态变更在 `Store` 内原子完成（内存实现使用单把互斥锁串行化）：

- 两个请求并发刷新同一旧令牌时，**最多一个轮换成功**，其余请求触发或观察到家族撤销，
  不会产生两个有效后继。
- 主动撤销与刷新竞争时，**撤销优先于尚未提交的新令牌**：撤销先提交则刷新失败、候选令牌被丢弃；
  刷新先提交则撤销随后使新令牌立即失效。两种时序下都不存在可用的后继令牌。
- 家族一旦撤销，其下所有代次的刷新令牌均不可用，访问令牌校验（即使令牌本身未过期）也立即失败。

## API

```go
store := tokenfamilies.NewMemoryStore()
svc, err := tokenfamilies.NewService(store, nil, tokenfamilies.DefaultConfig(), secret, auditLogger)

// 登录：创建令牌家族，签发第一代令牌对
pair, err := svc.Login("user-1")

// 刷新：轮换出下一代令牌对；idempotencyKey 可为空
next, err := svc.Refresh(pair.RefreshToken, "client-request-id")

// 主动撤销整个家族（幂等）
err = svc.Revoke(pair.FamilyID)

// 校验访问令牌，返回身份信息；家族撤销后立即失败
claims, err := svc.ValidateAccessToken(next.AccessToken)
```

`Store` 是接口，`MemoryStore` 为参考实现，可替换为数据库实现；
实现必须保证 `Refresh` 与 `RevokeFamily` 的原子性语义。

## 错误分类

| 错误 | 含义 |
| --- | --- |
| `ErrTokenInvalid` | 令牌不存在或无法识别 |
| `ErrTokenExpired` | 令牌已过期 |
| `ErrReplayDetected` | 旧刷新令牌被再次使用，家族已被撤销 |
| `ErrFamilyRevoked` | 家族已被撤销（主动撤销或重放触发） |
| `ErrIdempotencyConflict` | 同一幂等键被用于不同的请求 |
| `ErrFamilyNotFound` | 指定的家族不存在 |

## 运行测试

    go test -race ./...

测试覆盖：登录签发、轮换链、重放撤销、幂等重试与冲突、幂等窗口过期、
并发刷新单后继、撤销与刷新竞争、过期判断、无效令牌、持久化层无明文、
错误与日志无敏感值、审计事件。
