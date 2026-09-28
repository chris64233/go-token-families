package tokenfamilies

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Config 是服务的配置。
type Config struct {
	// AccessTokenTTL 是访问令牌的有效期。
	AccessTokenTTL time.Duration
	// RefreshTokenTTL 是每一代刷新令牌的有效期。
	RefreshTokenTTL time.Duration
	// IdempotencyWindow 是幂等重试窗口：窗口内凭同一幂等键可取回相同结果。
	IdempotencyWindow time.Duration
	// DeviceChangeTTL 是设备更换确认流程的短期有效期；过期后必须重新发起。
	DeviceChangeTTL time.Duration
	// SignatureFreshness 是设备请求签名允许的最大时钟偏差/传输时延：
	// 请求携带的签名时刻与服务端当前时刻相差超过该值即拒绝。
	SignatureFreshness time.Duration
	// Clock 是统一的当前时间来源；为 nil 时使用系统时钟。
	Clock Clock
	// Logger 用于审计日志；为 nil 时丢弃日志。
	// 日志中只会出现家族 ID、设备标识、绑定版本等非敏感字段，
	// 绝不包含令牌明文、公钥/私钥、签名或原始证明材料。
	Logger *slog.Logger
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.AccessTokenTTL <= 0 {
		out.AccessTokenTTL = 15 * time.Minute
	}
	if out.RefreshTokenTTL <= 0 {
		out.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if out.IdempotencyWindow <= 0 {
		out.IdempotencyWindow = 5 * time.Minute
	}
	if out.DeviceChangeTTL <= 0 {
		out.DeviceChangeTTL = 10 * time.Minute
	}
	if out.SignatureFreshness <= 0 {
		out.SignatureFreshness = 2 * time.Minute
	}
	if out.Clock == nil {
		out.Clock = SystemClock()
	}
	if out.Logger == nil {
		out.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return out
}

// TokenPair 是一次签发（登录、轮换或换绑）的结果。
type TokenPair struct {
	FamilyID              string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	// BindingVersion 是该令牌对签发时家族的设备绑定版本。
	BindingVersion int
}

// AccessClaims 是访问令牌校验通过后返回的信息。
// 校验通过即保证 BindingVersion 等于家族当前绑定版本、家族未撤销且令牌未过期；
// 版本落后或家族撤销时校验直接失败（ErrDeviceBindingChanged / ErrFamilyRevoked）。
type AccessClaims struct {
	FamilyID       string
	UserID         string
	ExpiresAt      time.Time
	BindingVersion int // 同时是家族当前的设备绑定版本
	// DeviceID 是家族当前绑定的设备标识。
	DeviceID string
}

// RefreshRequest 是一次设备绑定的刷新请求。
//
// 设备必须用其私钥对服务端规范化的请求内容签名；规范内容由
// SignPayload/RefreshPayload 定义，其中包含设备标识、设备公钥、
// 待轮换刷新令牌的摘要、签名时刻与幂等键，因此签名无法被挪用到其它请求。
type RefreshRequest struct {
	// RefreshToken 是当前持有的刷新令牌明文（仅用于计算摘要，不落盘）。
	RefreshToken string
	// Device 是当前设备的身份（含本轮出示的裸公钥，不落盘）。
	Device DeviceIdentity
	// Signature 是设备私钥对规范化刷新内容的 Ed25519 签名。
	Signature []byte
	// SignedAt 是设备生成签名的时刻，参与签名内容；
	// 与服务端时钟相差超过 Config.SignatureFreshness 的请求被拒绝，防止签名重放。
	SignedAt time.Time
	// IdempotencyKey 是可选的幂等键；非空时参与签名内容。
	IdempotencyKey string
}

// idemEntry 是幂等重试缓存项，仅存于内存，生命周期不超过幂等窗口。
type idemEntry struct {
	tokenDigest string
	pair        TokenPair
	expiresAt   time.Time
}

// idemKey 把幂等键限定在具体家族绑定版本的键空间内：
// 不同绑定版本（换绑前后）的相同字符串彼此不可见，
// 旧设备的迟到重试永远不可能取回新设备版本的结果。
func idemCacheKey(familyID string, bindingVersion int, key string) string {
	return fmt.Sprintf("%s:v%d:%s", familyID, bindingVersion, key)
}

// Service 提供登录签发、设备绑定刷新、受控设备更换、主动撤销与访问令牌校验。
// 所有状态变更都在同一把互斥锁下完成，保证：
//   - 并发刷新同一令牌时只有一个请求能完成轮换；
//   - 主动撤销与刷新/更换确认竞争时，撤销对尚未提交的新状态优先生效；
//   - 设备更换的“换绑 + 轮换”对所有观察者原子可见，两个设备永不同时具备刷新资格。
type Service struct {
	cfg   Config
	store Store

	mu    sync.Mutex
	state *State
	idem  map[string]*idemEntry
}

// NewService 从 Store 恢复状态并创建服务。
func NewService(store Store, cfg Config) (*Service, error) {
	state, err := store.Load()
	if err != nil {
		return nil, err
	}
	if state == nil {
		state = newState()
	}
	return &Service{
		cfg:   cfg.withDefaults(),
		store: store,
		state: state,
		idem:  make(map[string]*idemEntry),
	}, nil
}

// Login 创建一个绑定到指定设备的新令牌家族，并签发第一代访问令牌与刷新令牌。
// 持久化的只有设备标识与设备公钥摘要；设备公钥本身不保存。
func (s *Service) Login(userID string, device DeviceIdentity) (*TokenPair, error) {
	if userID == "" {
		return nil, fmt.Errorf("tokenfamilies: user id must not be empty")
	}
	if err := device.validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// 可能失败的随机生成全部前置，成功后才一次性修改状态。
	familyID, err := newFamilyID()
	if err != nil {
		return nil, err
	}
	now := s.cfg.Clock.Now()
	minted, err := s.mintPairLocked(now)
	if err != nil {
		return nil, err
	}
	fam := &Family{
		ID:             familyID,
		UserID:         userID,
		CreatedAt:      now,
		Binding:        DeviceBinding{DeviceID: device.ID, PublicKeyDigest: PublicKeyDigest(device.PublicKey), BoundAt: now},
		BindingVersion: 1,
	}
	s.state.Families[familyID] = fam
	pair := s.commitPairLocked(fam, 1, 1, minted)
	s.addEventLocked(familyID, EventLogin, 1, map[string]string{"device_id": device.ID})
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	s.cfg.Logger.Info("token family created",
		"family_id", familyID, "user_id", userID, "device_id", device.ID, "binding_version", 1)
	return pair, nil
}

// Refresh 用当前刷新令牌轮换出下一代令牌对，请求必须由家族当前绑定设备签名。
//
//   - 刷新成功后旧刷新令牌立即一次性失效；
//   - idempotencyKey 非空时，窗口内同一键 + 同一旧令牌的重试返回相同结果；
//     同一键搭配不同令牌返回 ErrIdempotencyConflict；
//   - 已失效的旧令牌被当前绑定设备再次使用视为重放，撤销整个家族并返回
//     ErrReplayDetected；
//   - 设备切换后，旧设备的迟到请求（即便幂等键仍在重试窗口内）返回
//     ErrDeviceMismatch/ErrDeviceBindingChanged，既不能取回新设备的令牌结果，
//     也不会触发重放撤销。
func (s *Service) Refresh(req RefreshRequest) (*TokenPair, error) {
	if req.RefreshToken == "" {
		return nil, ErrInvalidToken
	}
	if err := req.Device.validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	s.sweepIdemLocked(now)
	dgst := digest(req.RefreshToken)

	// 签名时刻新鲜度检查：限制被录制签名的可重放窗口。
	signedAt := req.SignedAt
	if signedAt.IsZero() {
		return nil, fmt.Errorf("tokenfamilies: signature timestamp must not be zero: %w", ErrInvalidSignature)
	}
	if drift := now.Sub(signedAt); drift > s.cfg.SignatureFreshness || drift < -s.cfg.SignatureFreshness {
		return nil, fmt.Errorf("tokenfamilies: signature timestamp outside freshness window: %w", ErrInvalidSignature)
	}

	// 先验签：签名内容必须与本次请求的规范化内容逐字节一致。
	if err := verifySignature(SignedRequest{
		Device:         req.Device,
		Payload:        RefreshPayload(req.RefreshToken, signedAt),
		Signature:      req.Signature,
		IdempotencyKey: req.IdempotencyKey,
	}); err != nil {
		return nil, err
	}

	rec, ok := s.state.RefreshTokens[dgst]
	if !ok {
		return nil, ErrInvalidToken
	}
	fam := s.state.Families[rec.FamilyID]
	if fam == nil {
		return nil, fmt.Errorf("tokenfamilies: refresh token record %q references missing family", rec.FamilyID)
	}
	// 撤销具有优先权：任何刷新路径都先观察撤销状态。
	if fam.Revoked {
		return nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	// 设备绑定校验先于消耗/幂等判断：旧设备在换绑后的迟到请求在此被拦截，
	// 既读不到幂等缓存中的新结果，也不会被当作重放而撤销家族。
	if !req.Device.matches(fam.Binding) {
		return nil, fmt.Errorf("tokenfamilies: device %q is not bound to family %s: %w", req.Device.ID, fam.ID, ErrDeviceMismatch)
	}
	if rec.BindingVersion != fam.BindingVersion {
		return nil, fmt.Errorf("tokenfamilies: refresh token bound at version %d, family %s now at version %d: %w",
			rec.BindingVersion, fam.ID, fam.BindingVersion, ErrDeviceBindingChanged)
	}

	if req.IdempotencyKey != "" {
		cacheKey := idemCacheKey(fam.ID, fam.BindingVersion, req.IdempotencyKey)
		if entry, ok := s.idem[cacheKey]; ok {
			// 缓存键已包含家族与绑定版本：此处只需校验同一旧令牌。
			// 换绑后旧设备的迟到请求在上方设备校验处即被拦截，根本到不了这里。
			if entry.tokenDigest != dgst {
				return nil, fmt.Errorf("tokenfamilies: idempotency key reused with a different refresh token: %w", ErrIdempotencyConflict)
			}
			pair := entry.pair
			return &pair, nil
		}
	}

	if rec.Consumed {
		if rec.ConsumeReason == consumeReasonDeviceChange {
			// 该令牌在设备更换时被原子轮换作废：不是攻击重放，返回绑定版本变更。
			return nil, fmt.Errorf("tokenfamilies: refresh token superseded by device change: %w", ErrDeviceBindingChanged)
		}
		// 旧令牌被当前绑定设备再次使用：判定为重放，撤销整个家族。
		s.revokeLocked(fam, "replay", now)
		s.addEventLocked(fam.ID, EventReplayRevoke, fam.BindingVersion, nil)
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		s.cfg.Logger.Warn("refresh token replay detected, family revoked",
			"family_id", fam.ID, "binding_version", fam.BindingVersion)
		return nil, fmt.Errorf("tokenfamilies: family %s revoked due to replay: %w", fam.ID, ErrReplayDetected)
	}
	if !now.Before(rec.ExpiresAt) {
		return nil, fmt.Errorf("tokenfamilies: refresh token expired at %s: %w", rec.ExpiresAt.UTC().Format(time.RFC3339), ErrTokenExpired)
	}

	// 轮换：先在任何状态变更前生成下一代令牌对（可能失败的步骤前置），
	// 成功后再把旧令牌一次性失效并登记新令牌。
	minted, err := s.mintPairLocked(now)
	if err != nil {
		return nil, err
	}
	rec.Consumed = true
	rec.ConsumedAt = &now
	rec.ConsumeReason = consumeReasonRotation
	pair := s.commitPairLocked(fam, rec.Generation+1, fam.BindingVersion, minted)
	s.addEventLocked(fam.ID, EventRefresh, fam.BindingVersion, map[string]string{"generation": fmt.Sprintf("%d", rec.Generation+1)})
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	if req.IdempotencyKey != "" {
		s.idem[idemCacheKey(fam.ID, fam.BindingVersion, req.IdempotencyKey)] = &idemEntry{
			tokenDigest: dgst,
			pair:        *pair,
			expiresAt:   now.Add(s.cfg.IdempotencyWindow),
		}
	}
	return pair, nil
}

// RevokeFamily 主动撤销一个令牌家族。撤销后该家族签发的所有刷新令牌
// 立即不可用，进行中的设备更换流程无法继续完成，访问令牌校验也会观察到撤销状态。
func (s *Service) RevokeFamily(familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fam, ok := s.state.Families[familyID]
	if !ok {
		return ErrFamilyNotFound
	}
	if fam.Revoked {
		return nil // 幂等：重复撤销不报错
	}
	now := s.cfg.Clock.Now()
	s.revokeLocked(fam, "manual", now)
	s.addEventLocked(fam.ID, EventManualRevoke, fam.BindingVersion, nil)
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.cfg.Logger.Info("token family revoked", "family_id", fam.ID, "reason", fam.Reason,
		"binding_version", fam.BindingVersion)
	return nil
}

// ValidateAccessToken 校验访问令牌，依次区分无效、已撤销、绑定版本变更、过期四种失败。
// 返回的 AccessClaims 反映令牌签发时的绑定版本；当它落后于家族当前版本时
// 校验直接失败，调用方无法把旧设备的访问令牌当作当前设备凭证使用。
func (s *Service) ValidateAccessToken(accessToken string) (*AccessClaims, error) {
	if accessToken == "" {
		return nil, ErrInvalidToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, fam, err := s.resolveAccessLocked(accessToken)
	if err != nil {
		return nil, err
	}
	return &AccessClaims{
		FamilyID:       rec.FamilyID,
		UserID:         rec.UserID,
		ExpiresAt:      rec.ExpiresAt,
		BindingVersion: rec.BindingVersion,
		DeviceID:       fam.Binding.DeviceID,
	}, nil
}

// resolveAccessLocked 做访问令牌的完整状态校验，供 ValidateAccessToken
// 与设备更换发起复用。调用方必须持有 s.mu。
func (s *Service) resolveAccessLocked(accessToken string) (*AccessTokenRecord, *Family, error) {
	rec, ok := s.state.AccessTokens[digest(accessToken)]
	if !ok {
		return nil, nil, ErrInvalidToken
	}
	fam := s.state.Families[rec.FamilyID]
	if fam == nil {
		return nil, nil, fmt.Errorf("tokenfamilies: access token record references missing family %q", rec.FamilyID)
	}
	if fam.Revoked {
		return nil, nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	if rec.BindingVersion != fam.BindingVersion {
		return nil, nil, fmt.Errorf("tokenfamilies: access token bound at version %d, family %s now at version %d: %w",
			rec.BindingVersion, fam.ID, fam.BindingVersion, ErrDeviceBindingChanged)
	}
	now := s.cfg.Clock.Now()
	if !now.Before(rec.ExpiresAt) {
		return nil, nil, fmt.Errorf("tokenfamilies: access token expired at %s: %w", rec.ExpiresAt.UTC().Format(time.RFC3339), ErrTokenExpired)
	}
	return rec, fam, nil
}

// DeviceSignature 是设备更换流程中单方（旧设备确认或新设备证明）的签名提交。
type DeviceSignature struct {
	// Device 是签名方设备身份（旧设备或新设备，含本轮出示的裸公钥）。
	Device DeviceIdentity
	// Signature 是设备私钥对该方规范内容的 Ed25519 签名。
	Signature []byte
}

// DeviceChangeStepResult 是确认/证明步骤的返回。
type DeviceChangeStepResult struct {
	// Status 是提交后流程的最新状态。
	Status *DeviceChangeStatus
	// TokenPair 仅在本次提交恰好使双方步骤齐备、换绑完成时非空。
	// 换绑产生的新令牌对只在这一次响应中明文返回；流程的任何重放都返回 nil。
	TokenPair *TokenPair
}

// InitiateDeviceChange 发起一次受控设备更换。
//
//   - 调用者必须出示当前绑定版本下有效的访问令牌；
//   - eventID 是调用方为本次“更换事件”生成的幂等标识：同事件 + 同内容重放
//     返回已有的待处理流程；同事件 + 不同新设备内容返回 ErrChangeConflict；
//   - 流程短期有效（Config.DeviceChangeTTL），过期后可用同一/新事件重新发起，
//     旧流程保留为 expired 且其迟到确认不可能影响新流程；
//   - 同一家族同时只允许存在一个未过期的待处理流程。
//
// 持久化记录中只出现新设备的标识与公钥摘要、一次性随机挑战等非敏感值，
// 不包含新设备公钥本身。
func (s *Service) InitiateDeviceChange(accessToken, eventID string, newDevice DeviceIdentity) (*DeviceChangeStatus, error) {
	if eventID == "" {
		return nil, fmt.Errorf("tokenfamilies: device change event id must not be empty: %w", ErrChangeConflict)
	}
	if err := newDevice.validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	_, fam, err := s.resolveAccessLocked(accessToken)
	if err != nil {
		return nil, err
	}

	// 同事件重放 / 冲突检测（先于"目标设备即当前设备"检查：已完成事件的目标
	// 设备天然就是当前绑定设备，同事件同内容重放仍应返回已有状态）。
	if existing := s.findChangeByEventLocked(fam.ID, eventID); existing != nil {
		sameContent := existing.NewDeviceID == newDevice.ID && existing.NewKeyDigest == PublicKeyDigest(newDevice.PublicKey)
		if existing.Status == changeCompleted {
			// 已完成事件：相同内容重放返回已有状态；不同内容一律冲突，
			// 不允许在同一事件下再挂一次更换。
			if sameContent {
				return s.statusOfLocked(existing, now), nil
			}
			return nil, fmt.Errorf("tokenfamilies: completed event %q reused with different content for family %s: %w",
				eventID, fam.ID, ErrChangeConflict)
		}
		if now.Before(existing.ExpiresAt) {
			if sameContent {
				return s.statusOfLocked(existing, now), nil
			}
			return nil, fmt.Errorf("tokenfamilies: event %q reused with different new device for family %s: %w",
				eventID, fam.ID, ErrChangeConflict)
		}
		// 旧流程已过期：落入下方重新发起，旧记录保留且不再可被确认。
	}

	// 新流程的目标设备不能与当前绑定设备完全相同。
	if newDevice.ID == fam.Binding.DeviceID && PublicKeyDigest(newDevice.PublicKey) == fam.Binding.PublicKeyDigest {
		return nil, fmt.Errorf("tokenfamilies: new device is identical to currently bound device: %w", ErrInvalidDevice)
	}

	// 同一家族只允许一个未过期的待处理流程。
	for _, rec := range s.state.DeviceChanges {
		if rec.FamilyID == fam.ID && rec.Status == changePending && now.Before(rec.ExpiresAt) {
			return nil, fmt.Errorf("tokenfamilies: family %s has an active device change %s: %w",
				fam.ID, rec.ID, ErrChangeInProgress)
		}
	}

	id, err := newChangeID()
	if err != nil {
		return nil, err
	}
	challenge, err := changeChallenge()
	if err != nil {
		return nil, err
	}
	rec := &DeviceChangeRecord{
		ID:             id,
		FamilyID:       fam.ID,
		EventID:        eventID,
		BindingVersion: fam.BindingVersion,
		OldDeviceID:    fam.Binding.DeviceID,
		OldKeyDigest:   fam.Binding.PublicKeyDigest,
		NewDeviceID:    newDevice.ID,
		NewKeyDigest:   PublicKeyDigest(newDevice.PublicKey),
		Challenge:      challenge,
		Status:         changePending,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.cfg.DeviceChangeTTL),
	}
	s.state.DeviceChanges[id] = rec
	s.addEventLocked(fam.ID, EventChangeInitiated, fam.BindingVersion,
		map[string]string{"change_id": id, "event_id": eventID, "new_device_id": newDevice.ID})
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	s.cfg.Logger.Info("device change initiated",
		"family_id", fam.ID, "change_id", id, "binding_version", fam.BindingVersion,
		"old_device_id", fam.Binding.DeviceID, "new_device_id", newDevice.ID)
	return s.statusOfLocked(rec, now), nil
}

// ConfirmDeviceChange 提交旧设备对更换流程的一次性确认。
// 签名内容见 OldConfirmPayload；重复提交相同确认是幂等的（返回当前状态）。
func (s *Service) ConfirmDeviceChange(changeID string, submission DeviceSignature) (*DeviceChangeStepResult, error) {
	return s.submitChangeStepLocked(changeID, submission, true)
}

// ProvideNewDeviceProof 提交新设备对更换流程的一次性证明。
// 签名内容见 NewProofPayload；重复提交相同证明是幂等的（返回当前状态）。
func (s *Service) ProvideNewDeviceProof(changeID string, submission DeviceSignature) (*DeviceChangeStepResult, error) {
	return s.submitChangeStepLocked(changeID, submission, false)
}

// submitChangeStepLocked 处理旧确认（old=true）或新证明（old=false）。
func (s *Service) submitChangeStepLocked(changeID string, submission DeviceSignature, old bool) (*DeviceChangeStepResult, error) {
	if err := submission.Device.validate(); err != nil {
		return nil, err
	}
	if len(submission.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("tokenfamilies: signature must be %d bytes: %w", ed25519.SignatureSize, ErrInvalidSignature)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	rec, ok := s.state.DeviceChanges[changeID]
	if !ok {
		return nil, ErrChangeNotFound
	}
	fam := s.state.Families[rec.FamilyID]
	if fam == nil {
		return nil, fmt.Errorf("tokenfamilies: change %s references missing family %q", rec.ID, rec.FamilyID)
	}
	// 撤销优先：家族撤销后任何迟到确认/证明都不得继续推进流程。
	if fam.Revoked {
		return nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	if rec.Status == changeCompleted {
		// 已完成流程的重放：返回已有状态，但绝不再次交付新令牌对。
		return &DeviceChangeStepResult{Status: s.statusOfLocked(rec, now)}, nil
	}
	if !now.Before(rec.ExpiresAt) {
		// 过期流程的迟到提交：不改变任何状态，也不可能影响之后发起的新流程
		//（新流程有独立的 ID 与挑战）。首次发现过期时清除挑战；
		// 审计事件与挑战清除统一持久化。
		if rec.Challenge != "" {
			rec.Challenge = ""
		}
		s.addEventLocked(fam.ID, EventChangeReplay, rec.BindingVersion, map[string]string{
			"change_id": rec.ID,
			"step":      stepName(old),
			"outcome":   "rejected_expired",
		})
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		s.cfg.Logger.Warn("late device change step rejected after expiry",
			"family_id", fam.ID, "change_id", rec.ID, "step", stepName(old))
		return nil, fmt.Errorf("tokenfamilies: device change %s expired at %s: %w",
			rec.ID, rec.ExpiresAt.UTC().Format(time.RFC3339), ErrChangeExpired)
	}

	// 绑定快照校验：旧确认必须来自发起时记录的旧设备，新证明必须来自目标新设备。
	wantID, wantDigest := rec.NewDeviceID, rec.NewKeyDigest
	var payload []byte
	if old {
		wantID, wantDigest = rec.OldDeviceID, rec.OldKeyDigest
		payload = OldConfirmPayload(rec.Challenge, rec.NewDeviceID, rec.NewKeyDigest)
	} else {
		payload = NewProofPayload(rec.Challenge, rec.OldDeviceID)
	}
	if submission.Device.ID != wantID || PublicKeyDigest(submission.Device.PublicKey) != wantDigest {
		return nil, fmt.Errorf("tokenfamilies: submitting device does not match %s device of change %s: %w",
			stepName(old), rec.ID, ErrDeviceMismatch)
	}
	if !ed25519.Verify(submission.Device.PublicKey,
		SignPayload(submission.Device.ID, submission.Device.PublicKey, payload, ""),
		submission.Signature) {
		return nil, ErrInvalidSignature
	}

	// 幂等地记录本方步骤；相同内容重复提交不会造成额外影响。
	if old && rec.OldConfirmedAt == nil {
		rec.OldConfirmedAt = &now
		s.addEventLocked(fam.ID, EventChangeOldConfirmed, rec.BindingVersion,
			map[string]string{"change_id": rec.ID})
	}
	if !old && rec.NewProvedAt == nil {
		rec.NewProvedAt = &now
		s.addEventLocked(fam.ID, EventChangeNewProved, rec.BindingVersion,
			map[string]string{"change_id": rec.ID})
	}

	result := &DeviceChangeStepResult{Status: s.statusOfLocked(rec, now)}
	if rec.OldConfirmedAt != nil && rec.NewProvedAt != nil {
		pair, err := s.completeChangeLocked(fam, rec, now)
		if err != nil {
			return nil, err
		}
		result.TokenPair = pair
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	result.Status = s.statusOfLocked(rec, now)
	return result, nil
}

// completeChangeLocked 在旧确认与新证明均齐备时，原子地把家族绑定切换到新设备
// 并立即轮换刷新令牌。调用方必须持有 s.mu；调用后状态已变更但尚未持久化，
// 由调用方统一持久化（保证“换绑 + 轮换”对观察者原子可见）。
func (s *Service) completeChangeLocked(fam *Family, rec *DeviceChangeRecord, now time.Time) (*TokenPair, error) {
	if fam.BindingVersion != rec.BindingVersion {
		// 理论上不可达：活动流程互斥 + 完成状态检查已排除并发换绑。
		return nil, fmt.Errorf("tokenfamilies: change %s stale: family binding moved to version %d: %w",
			rec.ID, fam.BindingVersion, ErrDeviceMismatch)
	}

	// 先计算新世代，并在任何状态变更之前生成新令牌对。
	// 若随机源失败，此处直接返回、状态零改动，不会留下"已换绑但无新令牌"的中间态。
	maxGeneration := 0
	for _, t := range s.state.RefreshTokens {
		if t.FamilyID == fam.ID && t.Generation > maxGeneration {
			maxGeneration = t.Generation
		}
	}
	minted, err := s.mintPairLocked(now)
	if err != nil {
		return nil, err
	}
	newGeneration := maxGeneration + 1

	// 以下变更不可再失败：作废当前绑定版本下所有尚未消耗的刷新令牌（正常只会有
	// 一个），确保旧设备在换绑完成的同一刻失去刷新资格。
	for _, t := range s.state.RefreshTokens {
		if t.FamilyID != fam.ID {
			continue
		}
		if t.BindingVersion == rec.BindingVersion && !t.Consumed {
			t.Consumed = true
			t.ConsumedAt = &now
			t.ConsumeReason = consumeReasonDeviceChange
		}
	}

	fam.Binding = DeviceBinding{
		DeviceID:        rec.NewDeviceID,
		PublicKeyDigest: rec.NewKeyDigest,
		BoundAt:         now,
	}
	fam.BindingVersion++

	// 旧绑定版本的幂等缓存全部作废：其中缓存的旧令牌对不得在换绑后被取回。
	prefix := fmt.Sprintf("%s:v%d:", fam.ID, rec.BindingVersion)
	for key := range s.idem {
		if strings.HasPrefix(key, prefix) {
			delete(s.idem, key)
		}
	}

	pair := s.commitPairLocked(fam, newGeneration, fam.BindingVersion, minted)
	rec.Status = changeCompleted
	rec.CompletedAt = &now
	rec.NewGeneration = newGeneration
	// 挑战已完成使命：从持久化记录中清除，避免无用的随机值长期落盘。
	rec.Challenge = ""
	s.addEventLocked(fam.ID, EventChangeCompleted, fam.BindingVersion, map[string]string{
		"change_id":      rec.ID,
		"old_device_id":  rec.OldDeviceID,
		"new_device_id":  rec.NewDeviceID,
		"new_generation": fmt.Sprintf("%d", rec.NewGeneration),
	})
	s.cfg.Logger.Info("device change completed",
		"family_id", fam.ID, "change_id", rec.ID,
		"new_binding_version", fam.BindingVersion, "new_generation", rec.NewGeneration)
	return pair, nil
}

// mintedPair 是已生成令牌明文、但尚未登记进状态的新令牌对。
type mintedPair struct {
	pair        TokenPair
	accessDgst  string
	refreshDgst string
	accessExp   time.Time
	refreshExp  time.Time
}

// mintPairLocked 只做可能失败的随机令牌生成，不修改任何状态。
// 调用方在它成功返回后再做状态变更，保证"生成失败 => 状态零改动"。
// 调用方必须持有 s.mu。
func (s *Service) mintPairLocked(now time.Time) (*mintedPair, error) {
	accessToken, err := newToken("at")
	if err != nil {
		return nil, err
	}
	refreshToken, err := newToken("rt")
	if err != nil {
		return nil, err
	}
	return &mintedPair{
		accessDgst:  digest(accessToken),
		refreshDgst: digest(refreshToken),
		accessExp:   now.Add(s.cfg.AccessTokenTTL),
		refreshExp:  now.Add(s.cfg.RefreshTokenTTL),
		pair: TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

// commitPairLocked 把已生成的令牌对登记到指定家族、世代与绑定版本下。
// 调用方必须持有 s.mu。
func (s *Service) commitPairLocked(fam *Family, generation, bindingVersion int, m *mintedPair) *TokenPair {
	s.state.AccessTokens[m.accessDgst] = &AccessTokenRecord{
		Digest:         m.accessDgst,
		FamilyID:       fam.ID,
		UserID:         fam.UserID,
		BindingVersion: bindingVersion,
		ExpiresAt:      m.accessExp,
	}
	s.state.RefreshTokens[m.refreshDgst] = &RefreshTokenRecord{
		Digest:         m.refreshDgst,
		FamilyID:       fam.ID,
		Generation:     generation,
		BindingVersion: bindingVersion,
		ExpiresAt:      m.refreshExp,
	}
	m.pair.FamilyID = fam.ID
	m.pair.AccessTokenExpiresAt = m.accessExp
	m.pair.RefreshTokenExpiresAt = m.refreshExp
	m.pair.BindingVersion = bindingVersion
	return &m.pair
}

// revokeLocked 标记家族撤销。调用方必须持有 s.mu。
func (s *Service) revokeLocked(fam *Family, reason string, now time.Time) {
	fam.Revoked = true
	fam.RevokedAt = &now
	fam.Reason = reason
}

// persistLocked 将当前状态写入 Store。调用方必须持有 s.mu。
func (s *Service) persistLocked() error {
	if err := s.store.Save(s.state); err != nil {
		return fmt.Errorf("tokenfamilies: persist state: %w", err)
	}
	return nil
}

// sweepIdemLocked 清理已过期的幂等缓存项。调用方必须持有 s.mu。
func (s *Service) sweepIdemLocked(now time.Time) {
	for key, entry := range s.idem {
		if !now.Before(entry.expiresAt) {
			delete(s.idem, key)
		}
	}
}

// addEventLocked 追加一条安全事件并截断历史。调用方必须持有 s.mu。
// detail 只允许放入非敏感的标识与枚举值。
func (s *Service) addEventLocked(familyID, eventType string, bindingVersion int, detail map[string]string) {
	id, err := newEventID()
	if err != nil {
		// 随机源异常时退化为时间戳派生标识，不阻断主流程。
		id = fmt.Sprintf("evt_%d", s.cfg.Clock.Now().UnixNano())
	}
	ev := &SecurityEvent{
		ID:             id,
		FamilyID:       familyID,
		Type:           eventType,
		At:             s.cfg.Clock.Now(),
		BindingVersion: bindingVersion,
		Detail:         detail,
	}
	events := append(s.state.SecurityEvents[familyID], ev)
	if len(events) > maxEventsPerFamily {
		events = events[len(events)-maxEventsPerFamily:]
	}
	s.state.SecurityEvents[familyID] = events
}

// findChangeByEventLocked 返回家族内指定事件的最近一次更换流程（没有则 nil）。
func (s *Service) findChangeByEventLocked(familyID, eventID string) *DeviceChangeRecord {
	var latest *DeviceChangeRecord
	for _, rec := range s.state.DeviceChanges {
		if rec.FamilyID != familyID || rec.EventID != eventID {
			continue
		}
		if latest == nil || rec.CreatedAt.After(latest.CreatedAt) {
			latest = rec
		}
	}
	return latest
}

func stepName(old bool) string {
	if old {
		return "old_confirm"
	}
	return "new_proof"
}

// newFamilyID 生成随机的家族 ID。
func newFamilyID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenfamilies: generate family id: %w", err)
	}
	return "fam_" + hex.EncodeToString(buf), nil
}

// newChangeID 生成随机的更换流程 ID。
func newChangeID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenfamilies: generate change id: %w", err)
	}
	return "devchg_" + hex.EncodeToString(buf), nil
}

// newEventID 生成随机的安全事件 ID。
func newEventID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "evt_" + hex.EncodeToString(buf), nil
}
