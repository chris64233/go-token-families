# go-token-families

用于承载会话令牌签发、轮换、设备绑定与撤销相关的 Go 服务代码。

开发环境：Go 1.23.0。

## 功能概述

包 `tokenfamilies` 实现了基于**令牌家族（token family）**的刷新令牌轮换机制，
并在此基础上提供**设备绑定**与**受控的可信设备更换**：

- **登录签发（绑定设备）**：`Login` 创建令牌家族时绑定设备标识与设备公钥摘要，
  并签发第一代访问令牌 / 刷新令牌。
- **设备签名的轮换**：`Refresh` 请求必须携带当前绑定设备对规范化请求内容的
  Ed25519 签名（含刷新令牌摘要、签名时刻与幂等键）；刷新成功后当前刷新令牌
  立即一次性失效，家族内世代（generation）单调递增。
- **重放检测**：已失效的旧刷新令牌被当前绑定设备再次使用时，判定为重放攻击，
  **立即撤销整个家族**。
- **受控设备更换**：`InitiateDeviceChange` 生成短期有效的一次性确认流程；
  旧设备确认与新设备证明都完成后，**在同一个原子步骤内**把家族绑定切换到新设备
  并立即轮换刷新令牌。
- **撤销优先**：主动撤销与刷新、更换确认并发竞争时，撤销始终优先生效；
  设备切换成功后，旧设备携带重试窗口内幂等键的迟到刷新也无法取回新设备结果。
- **幂等重试**：窗口内同一幂等键 + 同一旧令牌可取回相同结果；缓存按
  "家族 + 设备绑定版本"隔离。
- **主动撤销**：`RevokeFamily` 撤销整个家族，进行中的更换流程随之无法完成。
- **校验**：`ValidateAccessToken` 同时反映家族撤销状态与当前设备绑定版本。
- **查询**：提供设备更换进度、家族当前绑定版本与安全事件查询，返回内容全部脱敏。

## 设备绑定与请求签名

- 登录时传入 `DeviceIdentity{ID, PublicKey}`（Ed25519 裸公钥，32 字节）。
  服务端只持久化设备 ID 与公钥的 SHA-256 摘要，**公钥本身、私钥与任何原始
  证明材料都不落盘、不入日志**。
- 刷新请求 `RefreshRequest` 携带设备身份、签名与签名时刻 `SignedAt`。
  被签名内容由 `SignPayload` / `refreshPayload` 规范化：

  ```
  "tf1" | deviceID | rawPublicKey | "refresh" | refreshTokenDigest | signedAtUnixNano | idempotencyKey
  ```

  - 刷新令牌以**摘要**形式进入签名内容，区分令牌且不泄露明文；
  - 签名时刻与服务端时钟相差超过 `Config.SignatureFreshness` 即拒绝，
    限制被录制签名的可重放窗口；
  - 幂等键参与签名，签名无法被挪用到其它请求。

## 受控设备更换

流程分三步（两个签名步骤的先后顺序不限）：

1. `InitiateDeviceChange(accessToken, eventID, newDevice)`：凭当前版本有效的
   访问令牌发起，服务端生成随机流程 ID 与一次性**挑战（challenge）**，
   流程在 `Config.DeviceChangeTTL`（默认 10 分钟）内有效。
2. `ConfirmDeviceChange(changeID, oldDeviceSignature)`：旧设备用其私钥对
   `challenge + 新设备ID + 新设备公钥摘要` 签名确认。
3. `ProvideNewDeviceProof(changeID, newDeviceSignature)`：新设备用其私钥对
   `challenge + 旧设备ID` 签名，证明自己持有对应私钥。

两个步骤都齐备的那一刻，服务端在同一把锁、同一次持久化内：

1. 作废当前绑定版本下所有未消耗的刷新令牌（原因为 `device_change`，区别于攻击
   性重放，不会触发家族撤销）；
2. 家族绑定整体替换为新设备，绑定版本 +1；
3. 立即轮换并签发新版本的访问令牌 / 刷新令牌。

新令牌对**只在使流程完成的那一次响应中明文返回一次**；之后对已完成流程的任何
重放只返回状态，不再交付令牌。任一步失败（含撤销竞争）都不会出现两个设备同时
具备刷新资格的中间状态。

### 重放、冲突与过期

- **同事件同内容重放**：`eventID` 相同且新设备内容一致，返回已有流程状态；
- **同号异内容**：同一 `eventID` 搭配不同新设备返回 `ErrChangeConflict`
  （流程完成后同样适用）；
- **流程过期**：超过 TTL 后旧流程的迟到确认/证明返回 `ErrChangeExpired` 且不
  改变任何状态；可重新发起，新流程拥有独立 ID 与挑战，旧流程的迟到提交不可能
  影响新流程；
- **活动流程互斥**：同一家族同时只允许一个未过期的待处理流程。

### 撤销优先与旧设备迟到请求

- 家族撤销后，待处理更换流程的任何确认/证明都被拒绝，流程不可能完成；
- 换绑成功后，旧设备的刷新请求在设备绑定校验处即被拦截
  （`ErrDeviceMismatch`），既不会被误判为重放而撤销家族，也读不到幂等缓存；
- 幂等缓存按 `家族ID:绑定版本:键` 分区，并在换绑时清除旧版本分区，
  因此旧设备在重试窗口内携带相同幂等键也取不到新设备的令牌结果。

### 访问令牌校验反映绑定版本

每个访问令牌记录其签发时的绑定版本。`ValidateAccessToken` 依次区分：
无效 → 家族已撤销（`ErrFamilyRevoked`）→ 绑定版本已变更
（`ErrDeviceBindingChanged`）→ 已过期。设备切换后，旧设备尚未过期的访问令牌
立即不可用；校验通过时返回的 `BindingVersion` 即家族当前版本。

## 持久化只保存不可逆摘要

令牌明文只在签发响应中出现一次。持久化层（`Store`）仅保存：

- 访问 / 刷新令牌的 SHA-256 摘要、家族元数据与过期时间；
- 设备 ID 与设备公钥的 SHA-256 摘要（不保存公钥本身）；
- 更换流程的设备摘要、一次性挑战（仅待处理期内存在，完成或过期即清除）。

即使状态文件泄露也无法还原令牌或密钥。幂等重试缓存（含令牌明文）只驻留内存，
生命周期不超过幂等窗口，绝不落盘，并在设备换绑时按旧版本清除。

## 安全事件

以下动作会为家族记录一条安全事件（`ListSecurityEvents` 查询，每家族保留最近
100 条）：登录、刷新、主动撤销、重放撤销、更换发起、旧设备确认、新设备证明、
更换完成、过期流程的迟到提交。事件只含枚举类型、绑定版本、家族/设备/流程 ID
等非敏感字段。

## 统一的当前时间来源

过期判断、签名新鲜度窗口、更换流程有效期与幂等重试窗口都通过 `Config.Clock`
取值。生产环境使用系统时钟，测试可注入假时钟推进时间。

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
| `ErrInvalidDevice` | 设备标识或公钥格式非法 |
| `ErrDeviceMismatch` | 请求设备不是家族当前绑定设备（含旧设备换绑后的迟到请求） |
| `ErrInvalidSignature` | 签名缺失、被篡改、验签失败或超出新鲜度窗口 |
| `ErrDeviceBindingChanged` | 令牌的绑定版本已过期（设备已切换） |
| `ErrChangeNotFound` | 更换流程不存在 |
| `ErrChangeExpired` | 更换流程已过期 |
| `ErrChangeConflict` | 同一更换事件 ID 被用于不同内容 |
| `ErrChangeInProgress` | 家族已有未过期的待处理更换流程 |

日志与错误信息中只包含家族 ID、设备标识、流程 ID、绑定版本、过期时刻等非敏感
字段，绝不包含令牌明文、公钥/私钥、签名或原始证明材料。

## 使用示例

```go
store := tokenfamilies.NewFileStore("/var/lib/myapp/token-state.json")
svc, err := tokenfamilies.NewService(store, tokenfamilies.Config{
    AccessTokenTTL:     15 * time.Minute,
    RefreshTokenTTL:    30 * 24 * time.Hour,
    IdempotencyWindow:  5 * time.Minute,
    DeviceChangeTTL:    10 * time.Minute,
    SignatureFreshness: 2 * time.Minute,
    Clock:              tokenfamilies.SystemClock(),
})
if err != nil { /* ... */ }

// 登录：创建绑定到当前设备的令牌家族
pair, err := svc.Login("user-123", tokenfamilies.DeviceIdentity{
    ID:        "device-abc",
    PublicKey: devicePublicKey, // Ed25519
})

// 刷新：请求必须由当前设备签名（内容拼接见 SignPayload/RefreshPayload）
msg := tokenfamilies.SignPayload("device-abc", devicePublicKey,
    tokenfamilies.RefreshPayload(pair.RefreshToken, now), "req-uuid-0001")
next, err := svc.Refresh(tokenfamilies.RefreshRequest{
    RefreshToken:   pair.RefreshToken,
    Device:         tokenfamilies.DeviceIdentity{ID: "device-abc", PublicKey: devicePublicKey},
    Signature:      ed25519.Sign(devicePrivateKey, msg),
    SignedAt:       now,
    IdempotencyKey: "req-uuid-0001",
})

// 发起设备更换（凭当前访问令牌），随后由旧设备确认、新设备证明
change, err := svc.InitiateDeviceChange(next.AccessToken, "change-event-1",
    tokenfamilies.DeviceIdentity{ID: "device-xyz", PublicKey: newDevicePublicKey})

// 旧设备确认
oldMsg := tokenfamilies.SignPayload("device-abc", devicePublicKey,
    tokenfamilies.OldConfirmPayload(change.Challenge, change.NewDeviceID,
        tokenfamilies.PublicKeyDigest(newDevicePublicKey)), "")
_, _ = svc.ConfirmDeviceChange(change.ID, tokenfamilies.DeviceSignature{
    Device:    tokenfamilies.DeviceIdentity{ID: "device-abc", PublicKey: devicePublicKey},
    Signature: ed25519.Sign(devicePrivateKey, oldMsg),
})

// 新设备证明：该响应使流程完成，并唯一一次交付新设备的令牌对
newMsg := tokenfamilies.SignPayload("device-xyz", newDevicePublicKey,
    tokenfamilies.NewProofPayload(change.Challenge, change.OldDeviceID), "")
done, err := svc.ProvideNewDeviceProof(change.ID, tokenfamilies.DeviceSignature{
    Device:    tokenfamilies.DeviceIdentity{ID: "device-xyz", PublicKey: newDevicePublicKey},
    Signature: ed25519.Sign(newDevicePrivateKey, newMsg),
})
reboundPair := done.TokenPair // 仅此时非空

// 查询：更换进度 / 当前绑定 / 安全事件
progress, _ := svc.GetDeviceChange(change.ID)
binding, _  := svc.GetFamilyBinding(pair.FamilyID)
events, _   := svc.ListSecurityEvents(pair.FamilyID)

// 主动撤销（如用户登出、检测到异常）
err = svc.RevokeFamily(pair.FamilyID)
```

> 注：`RefreshPayload` / `OldConfirmPayload` / `NewProofPayload` 是导出的签名
> 内容协议构造函数，设备端与服务端必须使用与 `SignPayload` 完全一致的拼接；
> `RefreshPayload` 直接接收刷新令牌明文（内部只取摘要）。

## 持久化

`Store` 接口抽象了持久化层：

- `MemoryStore`：内存实现，适用于测试与嵌入式场景；
- `FileStore`：JSON 文件实现，临时文件 + 原子重命名写入，服务重启后状态
  （含进行中的更换流程与安全事件）可恢复。

## 测试

```sh
go test ./... -race
```

测试覆盖：设备绑定的登录签发、设备签名校验（设备不匹配/篡改签名/签名过期）、
多代轮换链、重放触发家族撤销、幂等重试与窗口过期、幂等键冲突、并发刷新唯一
胜者、撤销与刷新竞争、设备更换完整链路（两种步骤顺序）、换绑与轮换的原子性、
新令牌仅交付一次、更换事件重放与同号异内容冲突、流程过期后重新发起且旧流程
迟到确认隔离、撤销优先于更换确认（含三方并发 50 轮）、旧设备携带幂等键的迟到
刷新无法取回新设备结果、访问令牌反映绑定版本变更、更换进度/绑定/安全事件查询、
更换流程跨重启恢复，以及持久化文件、错误信息中不含令牌明文、裸公钥与签名。
