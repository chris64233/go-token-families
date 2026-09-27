# go-token-families

用于承载会话令牌签发、轮换与撤销相关的 Go 服务代码。

开发环境：Go 1.23.0。

## 功能概述

包 `tokenfamilies` 实现了基于**令牌家族（token family）**的刷新令牌轮换机制：

- **登录签发**：`Login` 创建一个令牌家族，并签发第一代访问令牌 / 刷新令牌。
- **轮换**：`Refresh` 成功后，当前刷新令牌立即一次性失效，同时签发下一代令牌对；家族内世代（generation）单调递增。
- **重放检测**：已失效的旧刷新令牌被再次使用时，判定为重放攻击，**立即撤销整个家族**，该家族已签发的所有刷新令牌与访问令牌全部失效。
- **幂等重试**：网络重试场景下，在有限窗口内凭同一幂等键 + 同一旧令牌可取回相同的轮换结果；同一幂等键搭配不同令牌返回幂等冲突错误。
- **主动撤销**：`RevokeFamily` 撤销整个家族；与刷新并发竞争时，撤销对尚未提交的新令牌优先生效。
- **校验**：`ValidateAccessToken` 校验访问令牌，能观察到家族的撤销状态。

## 设计要点

### 持久化只保存不可逆摘要

令牌明文只在签发响应中出现一次。持久化层（`Store`）仅保存令牌的 SHA-256
摘要、家族元数据与过期时间，即使状态文件泄露也无法还原令牌。
幂等重试缓存（含令牌明文）只驻留内存，生命周期不超过幂等窗口，绝不落盘。

### 统一的当前时间来源

过期判断与幂等重试窗口都通过 `Config.Clock` 取值。生产环境使用系统时钟，
测试可注入假时钟推进时间，保证所有时间口径一致。

### 并发语义

所有状态变更在同一把互斥锁下完成：

- 两个请求并发刷新同一令牌时，只有一个能完成轮换，不存在两个有效后继；
  另一个请求触发（或观察到）家族撤销。
- 主动撤销与刷新竞争时，无论谁先获得锁，最终家族必然处于撤销状态，
  不可能出现"撤销后仍签发出有效新令牌"的情况。

### 错误分类

调用方使用 `errors.Is` 区分失败原因：

| 错误 | 含义 |
| --- | --- |
| `ErrInvalidToken` | 令牌无法识别 |
| `ErrTokenExpired` | 令牌已过期 |
| `ErrReplayDetected` | 旧刷新令牌被重用，已触发家族撤销 |
| `ErrFamilyRevoked` | 家族已被撤销（主动撤销或重放触发） |
| `ErrIdempotencyConflict` | 同一幂等键被用于不同的刷新请求 |
| `ErrFamilyNotFound` | 指定的家族不存在 |

日志与错误信息中只包含家族 ID、过期时刻等非敏感字段，绝不包含令牌明文。

## 使用示例

```go
store := tokenfamilies.NewFileStore("/var/lib/myapp/token-state.json")
svc, err := tokenfamilies.NewService(store, tokenfamilies.Config{
    AccessTokenTTL:    15 * time.Minute,
    RefreshTokenTTL:   30 * 24 * time.Hour,
    IdempotencyWindow: 5 * time.Minute,
    Clock:             tokenfamilies.SystemClock(),
})
if err != nil { /* ... */ }

// 登录：创建令牌家族
pair, err := svc.Login("user-123")

// 刷新：轮换出下一代令牌对；idempotencyKey 用于网络重试
next, err := svc.Refresh(pair.RefreshToken, "req-uuid-0001")

// 校验访问令牌
claims, err := svc.ValidateAccessToken(next.AccessToken)

// 主动撤销（如用户登出、检测到异常）
err = svc.RevokeFamily(pair.FamilyID)
```

## 持久化

`Store` 接口抽象了持久化层：

- `MemoryStore`：内存实现，适用于测试与嵌入式场景；
- `FileStore`：JSON 文件实现，临时文件 + 原子重命名写入，服务重启后状态可恢复。

## 测试

```sh
go test ./... -race
```

测试覆盖：登录签发、多代轮换链、重放触发家族撤销、幂等重试与窗口过期、
幂等键冲突、并发刷新唯一胜者、撤销与刷新竞争、统一时钟过期判断、
服务重启后状态恢复，以及持久化文件与错误信息中不含令牌明文。
