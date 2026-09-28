# go-token-families

用于承载会话令牌签发、轮换与撤销相关的 Go 服务代码。

开发环境：Go 1.23.0。

## 功能概述

包 `tokenfamilies` 实现了基于**令牌家族（token family）**的刷新令牌轮换机制，
并在此之上提供**设备绑定**与**可控的可信设备更换**：

- **登录签发（设备绑定）**：`Login` 创建令牌家族时绑定设备标识及其公钥摘要，
  家族世代（generation）与设备绑定版本（binding version，初始为 1）单调递增。
- **设备签名的刷新**：`Refresh` 除携带刷新令牌外，还必须携带当前绑定设备
  对请求内容（刷新令牌 + 幂等键）的签名；设备标识或公钥摘要不匹配、签名无效
  的请求一律拒绝。
- **轮换**：`Refresh` 成功后，当前刷新令牌立即一次性失效，同时签发下一代令牌对。
- **重放检测**：已失效的旧刷新令牌被再次使用（且设备签名有效）时，判定为重放攻击，
  **立即撤销整个家族**。注意：未通过设备证明的旧令牌使用不会触发撤销，
  避免任何持有旧令牌的人都能注销家族。
- **设备更换**：`InitiateDeviceChange` 生成短期有效的一次性确认流程，
  需要**旧设备确认**与**新设备私钥证明**两步；两步汇合后在同一临界区内
  **原子地**把家族绑定切换到新设备并立即轮换刷新令牌。
- **幂等重试**：普通刷新与设备更换都支持幂等——同键同内容返回已有状态，
  同键异内容返回冲突错误。
- **撤销优先**：`RevokeFamily` 与刷新、更换确认/证明并发竞争时，撤销对尚未
  提交的结果优先生效。
- **校验**：`ValidateAccessToken` 反映家族当前的设备绑定版本与撤销状态；
  设备切换后，旧设备时代签发的访问令牌立即失效。
- **安全查询**：提供设备更换进度（`DeviceChangeStatus`）、家族当前绑定版本
  （`FamilyBinding`）与安全事件（`SecurityEvents`）查询，返回内容均不含敏感值。

## 设备绑定与设备更换

### 登录绑定

`Login(userID, deviceID, devicePublicKey)` 只持久化：

- 设备标识 `deviceID`；
- 设备公钥的 **SHA-256 摘要**（公钥本身绝不持久化）。

刷新请求 `RefreshRequest` 必须包含：

- `DeviceID` / `DevicePublicKey`：与家族当前绑定比对（标识 + 公钥摘要）；
- `Signature`：设备私钥对 `RefreshMessage(refreshToken, idempotencyKey)` 的签名。

默认签名算法为 Ed25519（`Ed25519Verifier`），可通过 `Config.Verifier` 替换。

### 两步一次性确认流程

```
InitiateDeviceChange(changeID, newDeviceID, newDevicePublicKey)
        │  生成一次性 Nonce，TTL = Config.DeviceChangeTTL（默认 10 分钟）
        ▼
旧设备 ConfirmDeviceChange  ──┐
                               ├── 两步都完成后原子提交
新设备 ProveDeviceChange   ──┘
        │
        ▼
绑定切换到新设备 + BindingVersion++ + 立即轮换刷新令牌（新令牌只交给新设备）
```

- 两步顺序不限：先证明后确认同样可以在第二步汇合时提交。
- 任一步失败（设备不匹配、签名无效、流程过期、家族已撤销）都不会改变绑定，
  **任何时刻都不存在新旧两个设备同时具备刷新资格的状态**。
- 提交时家族所有未消费的刷新令牌立即一次性失效；随后签发的新一代令牌
  只有新设备能用。世代号延续此前最大值，不会回退。
- 更换是正常流程，不会撤销家族；重放撤销只针对"已消费令牌被当前绑定设备再次使用"。

### 重放与冲突语义

| 场景 | 行为 |
| --- | --- |
| 相同 `changeID` + 相同内容重复发起 | 返回已有状态（Nonce 不变） |
| 相同 `changeID` + 不同内容（设备 ID 或公钥不同） | `ErrChangeConflict` |
| 流程过期后相同事件重新发起 | 生成**新 Nonce**，旧流程的迟到确认因签名对不上新 Nonce 而被拒绝 |
| 同一家族存在另一个进行中的更换 | 新发起取代旧流程，旧流程的迟到确认返回 `ErrChangeNotFound` |
| 提交后的迟到确认/证明 | 返回已提交状态，不重新轮换 |
| 家族被撤销 | 发起、确认、证明一律返回 `ErrFamilyRevoked` |

### 设备切换后旧设备的迟到请求

- 旧设备时代签发的**访问令牌**：校验返回 `ErrDeviceBindingChanged`；
- 旧设备持旧刷新令牌刷新：返回 `ErrDeviceMismatch`（设备校验先于重放判定，
  不会连累家族被撤销）；
- 旧设备对切换前请求的**迟到幂等重试**，即使幂等键仍在重试窗口内，
  也因缓存项记录的绑定版本与当前版本不一致而返回 `ErrDeviceBindingChanged`，
  无法取回任何令牌结果。

## 设计要点

### 持久化只保存不可逆摘要

令牌明文与设备公钥只在请求处理过程中短暂出现于内存。持久化层（`Store`）仅保存：

- 访问/刷新令牌的 SHA-256 摘要；
- 设备公钥的 SHA-256 摘要（用于绑定比对）；
- 家族元数据、绑定版本、过期时间与更换流程状态。

即使状态文件泄露，也无法还原令牌或公钥。设备私钥、公钥原文、签名等
**原始证明材料绝不持久化**；幂等重试缓存（含令牌明文）只驻留内存，
生命周期不超过幂等窗口，绝不落盘。日志与错误信息只包含家族 ID、
设备 ID、更换 ID、过期时刻等非敏感字段。

### 统一的当前时间来源

过期判断、幂等重试窗口与设备更换流程有效期都通过 `Config.Clock` 取值。
生产环境使用系统时钟，测试可注入假时钟推进时间，保证所有时间口径一致。

### 并发语义

所有状态变更在同一把互斥锁下完成：

- 两个请求并发刷新同一令牌时，只有一个能完成轮换，不存在两个有效后继；
- 设备更换的确认、证明、提交是原子的：提交前旧设备保持资格，
  提交后仅新设备具备资格；
- 主动撤销与刷新/更换竞争时，无论谁先获得锁，撤销一旦发生，
  尚未提交与已经提交但随家族一起撤销的令牌都不可用，
  不可能出现"撤销后仍有可用新令牌"的情况。

### 错误分类

调用方使用 `errors.Is` 区分失败原因：

| 错误 | 含义 |
| --- | --- |
| `ErrInvalidToken` | 令牌无法识别 |
| `ErrTokenExpired` | 令牌已过期 |
| `ErrReplayDetected` | 旧刷新令牌被当前绑定设备重用，已触发家族撤销 |
| `ErrFamilyRevoked` | 家族已被撤销（主动撤销或重放触发） |
| `ErrIdempotencyConflict` | 同一幂等键被用于不同的刷新请求 |
| `ErrFamilyNotFound` | 指定的家族不存在 |
| `ErrDeviceMismatch` | 设备标识或公钥摘要与当前绑定不符 |
| `ErrInvalidDeviceProof` | 设备签名校验失败 |
| `ErrDeviceBindingChanged` | 家族已绑定新设备（旧访问令牌 / 旧设备的迟到幂等重试） |
| `ErrChangeNotFound` | 更换流程不存在（或已被更新的流程取代） |
| `ErrChangeConflict` | 相同更换标识被用于不同内容 |
| `ErrChangeExpired` | 更换确认流程已过期，需重新发起 |
| `ErrChangeCommitted` | 更换已完成（提交后的迟到操作返回已提交状态而非报错） |

## 使用示例

```go
store := tokenfamilies.NewFileStore("/var/lib/myapp/token-state.json")
svc, err := tokenfamilies.NewService(store, tokenfamilies.Config{
    AccessTokenTTL:    15 * time.Minute,
    RefreshTokenTTL:   30 * 24 * time.Hour,
    IdempotencyWindow: 5 * time.Minute,
    DeviceChangeTTL:   10 * time.Minute,
    Clock:             tokenfamilies.SystemClock(),
})
if err != nil { /* ... */ }

// 登录：创建令牌家族并绑定设备（pub 为设备公钥，仅保存其摘要）
pair, err := svc.Login("user-123", "device-phone", pub)

// 刷新：必须携带当前设备对 RefreshMessage(...) 的签名
msg := tokenfamilies.RefreshMessage(pair.RefreshToken, "req-uuid-0001")
next, err := svc.Refresh(tokenfamilies.RefreshRequest{
    RefreshToken:    pair.RefreshToken,
    IdempotencyKey:  "req-uuid-0001",
    DeviceID:        "device-phone",
    DevicePublicKey: pub,
    Signature:       sign(priv, msg),
})

// 发起设备更换：changeID 作为更换事件的幂等键
st, err := svc.InitiateDeviceChange(tokenfamilies.DeviceChangeRequest{
    FamilyID:           pair.FamilyID,
    ChangeID:           "change-0001",
    NewDeviceID:        "device-laptop",
    NewDevicePublicKey: newPub,
})

// 旧设备确认（Nonce 来自 st）
confirmMsg := tokenfamilies.DeviceChangeConfirmMessage(
    pair.FamilyID, st.ChangeID, st.Nonce, "device-laptop",
    tokenfamilies.KeyDigest(newPub), // 见下方说明
)
_, err = svc.ConfirmDeviceChange(tokenfamilies.ConfirmChangeRequest{
    FamilyID: pair.FamilyID, ChangeID: st.ChangeID,
    DeviceID: "device-phone", DevicePublicKey: pub,
    Signature: sign(oldPriv, confirmMsg),
})

// 新设备证明；第二步汇合时原子提交并返回轮换后的新令牌对
proveMsg := tokenfamilies.DeviceChangeProveMessage(pair.FamilyID, st.ChangeID, st.Nonce)
out, err := svc.ProveDeviceChange(tokenfamilies.ProveChangeRequest{
    FamilyID: pair.FamilyID, ChangeID: st.ChangeID,
    DeviceID: "device-laptop", DevicePublicKey: newPub,
    Signature: sign(newPriv, proveMsg),
})
newPair := out.Tokens // 仅提交发生的那一步返回

// 校验访问令牌（反映当前绑定版本与撤销状态）
claims, err := svc.ValidateAccessToken(newPair.AccessToken)

// 查询：更换进度 / 当前绑定 / 安全事件
progress, _ := svc.DeviceChangeStatus(pair.FamilyID, "change-0001")
binding, _  := svc.FamilyBinding(pair.FamilyID)
events, _   := svc.SecurityEvents(pair.FamilyID)

// 主动撤销（如用户登出、检测到异常）
err = svc.RevokeFamily(pair.FamilyID)
```

> 说明：设备公钥摘要由服务内部计算（登录、发起更换时），上面的
> `KeyDigest` 仅用于客户端构造旧设备的确认签名消息；若不想暴露该函数，
> 也可由应用层用同样的 SHA-256（十六进制）约定自行计算。

## 持久化

`Store` 接口抽象了持久化层：

- `MemoryStore`：内存实现，适用于测试与嵌入式场景；
- `FileStore`：JSON 文件实现，临时文件 + 原子重命名写入，服务重启后状态可恢复
  （包括进行中的设备更换流程与防重放 Nonce）。

## 测试

```sh
go test ./... -race
```

测试覆盖：登录与设备绑定、刷新签名校验（设备不符 / 公钥不符 / 签名无效）、
未授权重放不得撤销家族、多代轮换链、重放触发家族撤销、幂等重试与窗口过期、
幂等键冲突、并发刷新唯一胜者、撤销与刷新竞争、设备更换完整流程（两种步骤顺序）、
更换步骤幂等与提交后迟到操作、错误设备/坏签名不得推进、更换发起重放与同号异内容冲突、
过期后重新发起且旧 Nonce 迟到确认无效、新流程取代旧流程、撤销与更换竞争、
提交与撤销并发、设备切换后旧设备迟到幂等重试被拒绝、确认与证明并发只提交一次、
进度/绑定/事件查询、更换流程跨重启恢复，以及持久化文件与查询视图中
不含令牌明文、公钥原文或证明材料。
