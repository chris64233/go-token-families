package tokenfamilies

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
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
	// DeviceChangeTTL 是设备更换确认流程的有效期，过期后需重新发起。
	DeviceChangeTTL time.Duration
	// Verifier 校验设备对请求内容的签名；为 nil 时使用 Ed25519。
	Verifier SignatureVerifier
	// Clock 是统一的当前时间来源；为 nil 时使用系统时钟。
	Clock Clock
	// Logger 用于审计日志；为 nil 时丢弃日志。
	// 日志中只会出现家族 ID、设备 ID 等非敏感字段，
	// 绝不包含令牌明文、公钥或签名。
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
	if out.Verifier == nil {
		out.Verifier = Ed25519Verifier()
	}
	if out.Clock == nil {
		out.Clock = SystemClock()
	}
	if out.Logger == nil {
		out.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return out
}

// TokenPair 是一次签发（登录、轮换或设备更换提交）的结果。
type TokenPair struct {
	FamilyID              string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// AccessClaims 是访问令牌校验通过后返回的信息。
type AccessClaims struct {
	FamilyID  string
	UserID    string
	ExpiresAt time.Time
	// DeviceID 与 BindingVersion 反映家族当前的设备绑定。
	DeviceID       string
	BindingVersion int
}

// idemEntry 是幂等重试缓存项，仅存于内存，生命周期不超过幂等窗口。
type idemEntry struct {
	tokenDigest string
	familyID    string
	// bindingVersion 是轮换发生时的设备绑定版本；设备切换后，
	// 旧设备的迟到重试不得再取回缓存的令牌结果。
	bindingVersion int
	pair           TokenPair
	expiresAt      time.Time
}

// Service 提供登录签发、刷新轮换、设备更换、主动撤销与访问令牌校验。
// 所有状态变更都在同一把互斥锁下完成，保证：
//   - 并发刷新同一令牌时只有一个请求能完成轮换；
//   - 设备更换的确认、证明与提交是原子的，任何失败都不会让
//     新旧两个设备同时具备刷新资格；
//   - 主动撤销与刷新/更换竞争时，撤销对尚未提交的结果优先生效。
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

// Login 创建一个新的令牌家族，绑定设备标识及其公钥摘要，
// 并签发第一代访问令牌与刷新令牌。
// 公钥只用于计算不可逆摘要，绝不持久化或写入日志。
func (s *Service) Login(userID, deviceID string, devicePublicKey []byte) (*TokenPair, error) {
	if userID == "" {
		return nil, fmt.Errorf("tokenfamilies: user id must not be empty")
	}
	if deviceID == "" {
		return nil, fmt.Errorf("tokenfamilies: device id must not be empty")
	}
	if len(devicePublicKey) == 0 {
		return nil, fmt.Errorf("tokenfamilies: device public key must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	familyID, err := newFamilyID()
	if err != nil {
		return nil, err
	}
	now := s.cfg.Clock.Now()
	fam := &Family{
		ID:              familyID,
		UserID:          userID,
		CreatedAt:       now,
		DeviceID:        deviceID,
		DeviceKeyDigest: keyDigest(devicePublicKey),
		BindingVersion:  1,
		BoundAt:         now,
	}
	s.state.Families[familyID] = fam
	pair, err := s.issueLocked(fam, 1, now)
	if err != nil {
		return nil, err
	}
	s.recordEventLocked(fam, EventLogin, "device="+deviceID, now)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	s.cfg.Logger.Info("token family created", "family_id", familyID, "user_id", userID, "device_id", deviceID)
	return pair, nil
}

// RefreshRequest 是一次刷新请求。除刷新令牌外，还必须携带当前绑定设备
// 对请求内容的签名，以证明请求确实来自持有设备私钥的设备。
type RefreshRequest struct {
	RefreshToken   string
	IdempotencyKey string
	DeviceID       string
	// DevicePublicKey 是设备公钥，仅用于本次校验（与绑定摘要比对并验签），
	// 绝不持久化或写入日志。
	DevicePublicKey []byte
	// Signature 是设备私钥对 RefreshMessage(RefreshToken, IdempotencyKey) 的签名。
	Signature []byte
}

// Refresh 用当前刷新令牌轮换出下一代令牌对。
//
//   - 请求必须通过设备绑定校验：设备标识与公钥摘要匹配家族当前绑定，
//     且签名有效；否则分别返回 ErrDeviceMismatch / ErrInvalidDeviceProof；
//   - 刷新成功后旧刷新令牌立即一次性失效；
//   - idempotencyKey 非空时，窗口内同一键 + 同一旧令牌的重试返回相同结果；
//     同一键搭配不同令牌返回 ErrIdempotencyConflict；
//     设备切换后旧设备的迟到重试不得取回结果，返回 ErrDeviceBindingChanged；
//   - 已失效的旧令牌被再次使用（且设备证明有效）视为重放，
//     撤销整个家族并返回 ErrReplayDetected。
func (s *Service) Refresh(req RefreshRequest) (*TokenPair, error) {
	if req.RefreshToken == "" {
		return nil, ErrInvalidToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	s.sweepIdemLocked(now)
	dgst := digest(req.RefreshToken)

	if req.IdempotencyKey != "" {
		if entry, ok := s.idem[req.IdempotencyKey]; ok {
			if entry.tokenDigest != dgst {
				return nil, fmt.Errorf("tokenfamilies: idempotency key reused with a different refresh token: %w", ErrIdempotencyConflict)
			}
			fam := s.state.Families[entry.familyID]
			if fam == nil {
				return nil, fmt.Errorf("tokenfamilies: idempotency entry references missing family %q", entry.familyID)
			}
			// 撤销优先于一切缓存结果。
			if fam.Revoked {
				return nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
			}
			// 设备已切换：旧设备的迟到重试（即使幂等键仍在窗口内）
			// 不得取回新设备的令牌结果。
			if fam.BindingVersion != entry.bindingVersion {
				return nil, fmt.Errorf("tokenfamilies: family %s bound to a new device: %w", fam.ID, ErrDeviceBindingChanged)
			}
			// 绑定未变，仍要求请求来自当前绑定设备且签名有效。
			if req.DeviceID != fam.DeviceID || keyDigest(req.DevicePublicKey) != fam.DeviceKeyDigest {
				return nil, fmt.Errorf("tokenfamilies: family %s bound to another device: %w", fam.ID, ErrDeviceMismatch)
			}
			if !s.cfg.Verifier.Verify(req.DevicePublicKey, RefreshMessage(req.RefreshToken, req.IdempotencyKey), req.Signature) {
				return nil, fmt.Errorf("tokenfamilies: family %s device proof rejected: %w", fam.ID, ErrInvalidDeviceProof)
			}
			pair := entry.pair
			return &pair, nil
		}
	}

	rec, ok := s.state.RefreshTokens[dgst]
	if !ok {
		return nil, ErrInvalidToken
	}
	fam := s.state.Families[rec.FamilyID]
	if fam == nil {
		return nil, fmt.Errorf("tokenfamilies: refresh token record %q references missing family", rec.FamilyID)
	}
	if fam.Revoked {
		return nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	// 设备绑定校验必须先于重放判定：未通过设备证明的请求
	// 不允许触发家族撤销，避免任何持有旧令牌的人都能注销整个家族。
	if req.DeviceID != fam.DeviceID || keyDigest(req.DevicePublicKey) != fam.DeviceKeyDigest {
		return nil, fmt.Errorf("tokenfamilies: family %s bound to another device: %w", fam.ID, ErrDeviceMismatch)
	}
	if !s.cfg.Verifier.Verify(req.DevicePublicKey, RefreshMessage(req.RefreshToken, req.IdempotencyKey), req.Signature) {
		return nil, fmt.Errorf("tokenfamilies: family %s device proof rejected: %w", fam.ID, ErrInvalidDeviceProof)
	}
	if rec.Consumed {
		// 旧令牌被再次使用：判定为重放，撤销整个家族。
		s.revokeLocked(fam, "replay", now)
		s.recordEventLocked(fam, EventReplayRevoke, "", now)
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		s.cfg.Logger.Warn("refresh token replay detected, family revoked", "family_id", fam.ID)
		return nil, fmt.Errorf("tokenfamilies: family %s revoked due to replay: %w", fam.ID, ErrReplayDetected)
	}
	if !now.Before(rec.ExpiresAt) {
		return nil, fmt.Errorf("tokenfamilies: refresh token expired at %s: %w", rec.ExpiresAt.UTC().Format(time.RFC3339), ErrTokenExpired)
	}

	// 轮换：旧令牌一次性失效，签发下一代令牌对。
	rec.Consumed = true
	rec.ConsumedAt = &now
	pair, err := s.issueLocked(fam, rec.Generation+1, now)
	if err != nil {
		return nil, err
	}
	s.recordEventLocked(fam, EventRefresh, fmt.Sprintf("generation=%d", rec.Generation+1), now)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	if req.IdempotencyKey != "" {
		s.idem[req.IdempotencyKey] = &idemEntry{
			tokenDigest:    dgst,
			familyID:       fam.ID,
			bindingVersion: fam.BindingVersion,
			pair:           *pair,
			expiresAt:      now.Add(s.cfg.IdempotencyWindow),
		}
	}
	return pair, nil
}

// RevokeFamily 主动撤销一个令牌家族。撤销后该家族签发的所有刷新令牌
// 立即不可用，访问令牌校验也会观察到撤销状态；与刷新或设备更换竞争时，
// 撤销对尚未提交的结果优先生效。
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
	s.revokeLocked(fam, "manual", s.cfg.Clock.Now())
	s.recordEventLocked(fam, EventManualRevoke, "", *fam.RevokedAt)
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.cfg.Logger.Info("token family revoked", "family_id", fam.ID, "reason", fam.Reason)
	return nil
}

// ValidateAccessToken 校验访问令牌，依次区分无效、已撤销、
// 设备绑定已变更、过期四种失败。校验结果反映家族当前的
// 设备绑定版本与撤销状态。
func (s *Service) ValidateAccessToken(accessToken string) (*AccessClaims, error) {
	if accessToken == "" {
		return nil, ErrInvalidToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.state.AccessTokens[digest(accessToken)]
	if !ok {
		return nil, ErrInvalidToken
	}
	fam := s.state.Families[rec.FamilyID]
	if fam == nil {
		return nil, fmt.Errorf("tokenfamilies: access token record references missing family %q", rec.FamilyID)
	}
	if fam.Revoked {
		return nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	if rec.BindingVersion != fam.BindingVersion {
		// 设备已切换：旧设备时代签发的访问令牌立即失效。
		return nil, fmt.Errorf("tokenfamilies: family %s bound to a new device: %w", fam.ID, ErrDeviceBindingChanged)
	}
	now := s.cfg.Clock.Now()
	if !now.Before(rec.ExpiresAt) {
		return nil, fmt.Errorf("tokenfamilies: access token expired at %s: %w", rec.ExpiresAt.UTC().Format(time.RFC3339), ErrTokenExpired)
	}
	return &AccessClaims{
		FamilyID:       rec.FamilyID,
		UserID:         rec.UserID,
		ExpiresAt:      rec.ExpiresAt,
		DeviceID:       fam.DeviceID,
		BindingVersion: fam.BindingVersion,
	}, nil
}

// issueLocked 生成并登记新一代令牌对。调用方必须持有 s.mu。
func (s *Service) issueLocked(fam *Family, generation int, now time.Time) (*TokenPair, error) {
	accessToken, err := newToken("at")
	if err != nil {
		return nil, err
	}
	refreshToken, err := newToken("rt")
	if err != nil {
		return nil, err
	}
	accessExp := now.Add(s.cfg.AccessTokenTTL)
	refreshExp := now.Add(s.cfg.RefreshTokenTTL)
	s.state.AccessTokens[digest(accessToken)] = &AccessTokenRecord{
		Digest:         digest(accessToken),
		FamilyID:       fam.ID,
		UserID:         fam.UserID,
		ExpiresAt:      accessExp,
		BindingVersion: fam.BindingVersion,
	}
	s.state.RefreshTokens[digest(refreshToken)] = &RefreshTokenRecord{
		Digest:     digest(refreshToken),
		FamilyID:   fam.ID,
		Generation: generation,
		ExpiresAt:  refreshExp,
	}
	return &TokenPair{
		FamilyID:              fam.ID,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
	}, nil
}

// revokeLocked 标记家族撤销。调用方必须持有 s.mu。
func (s *Service) revokeLocked(fam *Family, reason string, now time.Time) {
	fam.Revoked = true
	fam.RevokedAt = &now
	fam.Reason = reason
}

// recordEventLocked 追加一条安全事件，每个家族最多保留最近若干条。
// 事件只包含非敏感元数据。调用方必须持有 s.mu。
func (s *Service) recordEventLocked(fam *Family, eventType, detail string, now time.Time) {
	evs := append(s.state.Events[fam.ID], SecurityEvent{
		Type:           eventType,
		At:             now,
		FamilyID:       fam.ID,
		Detail:         detail,
		BindingVersion: fam.BindingVersion,
	})
	if len(evs) > maxEventsPerFamily {
		evs = append([]SecurityEvent(nil), evs[len(evs)-maxEventsPerFamily:]...)
	}
	s.state.Events[fam.ID] = evs
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

// newFamilyID 生成随机的家族 ID。
func newFamilyID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenfamilies: generate family id: %w", err)
	}
	return "fam_" + hex.EncodeToString(buf), nil
}

// newNonce 生成设备更换流程的随机防重放因子。
func newNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenfamilies: generate change nonce: %w", err)
	}
	return "nc_" + hex.EncodeToString(buf), nil
}
