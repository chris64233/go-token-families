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
	// Clock 是统一的当前时间来源；为 nil 时使用系统时钟。
	Clock Clock
	// Logger 用于审计日志；为 nil 时丢弃日志。
	// 日志中只会出现家族 ID 等非敏感字段，绝不包含令牌明文。
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
	if out.Clock == nil {
		out.Clock = SystemClock()
	}
	if out.Logger == nil {
		out.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return out
}

// TokenPair 是一次签发（登录或轮换）的结果。
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
}

// idemEntry 是幂等重试缓存项，仅存于内存，生命周期不超过幂等窗口。
type idemEntry struct {
	tokenDigest   string
	familyID      string
	deviceVersion int
	pair          TokenPair
	expiresAt     time.Time
}

// Service 提供登录签发、刷新轮换、主动撤销与访问令牌校验。
// 所有状态变更都在同一把互斥锁下完成，保证：
//   - 并发刷新同一令牌时只有一个请求能完成轮换；
//   - 主动撤销与刷新竞争时，撤销对尚未提交的新令牌优先生效。
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

// Login 创建一个新的令牌家族，绑定指定设备，并签发第一代访问令牌与刷新令牌。
// 同一用户在不同设备上登录会创建相互独立的家族。
func (s *Service) Login(userID, deviceID string) (*TokenPair, error) {
	if userID == "" {
		return nil, fmt.Errorf("tokenfamilies: user id must not be empty")
	}
	if deviceID == "" {
		return nil, fmt.Errorf("tokenfamilies: device id must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	familyID, err := newFamilyID()
	if err != nil {
		return nil, err
	}
	now := s.cfg.Clock.Now()
	s.state.Families[familyID] = &Family{
		ID:            familyID,
		UserID:        userID,
		DeviceID:      deviceID,
		DeviceVersion: 1,
		CreatedAt:     now,
	}
	fam := s.state.Families[familyID]
	pair, err := s.issueLocked(fam, 1, now)
	if err != nil {
		return nil, err
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	s.cfg.Logger.Info("token family created", "family_id", familyID, "user_id", userID, "device_id", deviceID)
	return pair, nil
}

// Refresh 用当前刷新令牌轮换出下一代令牌对。
//
//   - 刷新在同一把锁下锁定令牌家族、设备绑定与当前序号：
//     令牌签发时记录的设备绑定版本必须与家族当前版本一致；
//   - 刷新成功后旧刷新令牌立即一次性失效；
//   - idempotencyKey 非空时，窗口内同一键 + 同一旧令牌的重试返回相同结果；
//     同一键搭配不同令牌、或重试时设备绑定版本已变化，返回 ErrIdempotencyConflict；
//   - 已失效的旧令牌被再次使用视为重放，撤销整个家族并返回 ErrReplayDetected；
//   - 重放先被发现时，随后到达的合法刷新只能观察到撤销原因（ErrFamilyRevoked），
//     不会重新开启新链。
func (s *Service) Refresh(refreshToken, idempotencyKey string) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	s.sweepIdemLocked(now)
	dgst := digest(refreshToken)

	if idempotencyKey != "" {
		if entry, ok := s.idem[idempotencyKey]; ok {
			if entry.tokenDigest != dgst {
				return nil, fmt.Errorf("tokenfamilies: idempotency key reused with a different refresh token: %w", ErrIdempotencyConflict)
			}
			fam := s.state.Families[entry.familyID]
			if fam == nil || fam.DeviceVersion != entry.deviceVersion {
				return nil, fmt.Errorf("tokenfamilies: idempotency key reused after device binding changed: %w", ErrIdempotencyConflict)
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
	if rec.DeviceID != fam.DeviceID || rec.DeviceVersion != fam.DeviceVersion {
		return nil, fmt.Errorf("tokenfamilies: device binding changed for family %s: %w", fam.ID, ErrDeviceBindingChanged)
	}
	if rec.Consumed {
		// 旧令牌被再次使用：判定为重放，撤销整个家族。
		ev := s.replayRevokeLocked(fam, rec.Generation, now)
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		s.cfg.Logger.Warn("refresh token replay detected, family revoked",
			"family_id", fam.ID, "event_seq", ev.Seq, "generation", rec.Generation, "device_id", rec.DeviceID)
		return nil, fmt.Errorf("tokenfamilies: family %s revoked due to replay (event %d): %w", fam.ID, ev.Seq, ErrReplayDetected)
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
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	if idempotencyKey != "" {
		s.idem[idempotencyKey] = &idemEntry{
			tokenDigest:   dgst,
			familyID:      fam.ID,
			deviceVersion: fam.DeviceVersion,
			pair:          *pair,
			expiresAt:     now.Add(s.cfg.IdempotencyWindow),
		}
	}
	return pair, nil
}

// RevokeFamily 主动撤销一个令牌家族。撤销后该家族签发的所有刷新令牌
// 立即不可用，访问令牌校验也会观察到撤销状态。
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
	ev := s.appendEventLocked(EventTypeRevoke, fam, fam.Generation, "manual", now)
	s.revokeLocked(fam, "manual", ev.Seq, now)
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.cfg.Logger.Info("token family revoked", "family_id", fam.ID, "reason", fam.Reason, "event_seq", ev.Seq)
	return nil
}

// UnbindDevice 解除家族的设备绑定：设备绑定版本递增，该设备签发的
// 所有刷新令牌立即失效；若家族尚未撤销，则同时以 "device_unbind" 原因撤销。
// 解绑与撤销都会记录事件，保留二者的先后关系；家族已被撤销时
// 解绑只追加解绑事件，不会覆盖原有撤销原因，也不能恢复已撤销的家族。
func (s *Service) UnbindDevice(familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fam, ok := s.state.Families[familyID]
	if !ok {
		return ErrFamilyNotFound
	}
	if fam.DeviceID == "" {
		return nil // 幂等：重复解绑不报错
	}
	now := s.cfg.Clock.Now()
	deviceID := fam.DeviceID
	unbindEv := s.appendEventLocked(EventTypeDeviceUnbind, fam, fam.Generation, "", now)
	fam.DeviceID = ""
	fam.DeviceVersion++
	if !fam.Revoked {
		ev := s.appendEventLocked(EventTypeRevoke, fam, fam.Generation, "device_unbind", now)
		s.revokeLocked(fam, "device_unbind", ev.Seq, now)
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.cfg.Logger.Info("device unbound", "family_id", fam.ID, "device_id", deviceID, "event_seq", unbindEv.Seq)
	return nil
}

// ValidateAccessToken 校验访问令牌，依次区分无效、已撤销、过期三种失败。
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
	now := s.cfg.Clock.Now()
	if !now.Before(rec.ExpiresAt) {
		return nil, fmt.Errorf("tokenfamilies: access token expired at %s: %w", rec.ExpiresAt.UTC().Format(time.RFC3339), ErrTokenExpired)
	}
	return &AccessClaims{
		FamilyID:  rec.FamilyID,
		UserID:    rec.UserID,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

// issueLocked 生成并登记新一代令牌对，同时推进家族当前序号。
// 新令牌锁定家族当前的设备绑定。调用方必须持有 s.mu。
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
		Digest:     digest(accessToken),
		FamilyID:   fam.ID,
		UserID:     fam.UserID,
		Generation: generation,
		ExpiresAt:  accessExp,
	}
	s.state.RefreshTokens[digest(refreshToken)] = &RefreshTokenRecord{
		Digest:        digest(refreshToken),
		FamilyID:      fam.ID,
		Generation:    generation,
		DeviceID:      fam.DeviceID,
		DeviceVersion: fam.DeviceVersion,
		ExpiresAt:     refreshExp,
	}
	fam.Generation = generation
	return &TokenPair{
		FamilyID:              fam.ID,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
	}, nil
}

// revokeLocked 标记家族撤销。调用方必须持有 s.mu。
func (s *Service) revokeLocked(fam *Family, reason string, eventSeq int64, now time.Time) {
	fam.Revoked = true
	fam.RevokedAt = &now
	fam.Reason = reason
	fam.RevokedByEvent = eventSeq
}

// appendEventLocked 追加一条事件并返回。事件序号全局单调递增，
// 用于保留重放、撤销与设备解绑之间的先后关系。调用方必须持有 s.mu。
func (s *Service) appendEventLocked(eventType string, fam *Family, generation int, reason string, now time.Time) *Event {
	ev := &Event{
		Seq:        int64(len(s.state.Events)) + 1,
		Type:       eventType,
		FamilyID:   fam.ID,
		DeviceID:   fam.DeviceID,
		Generation: generation,
		Reason:     reason,
		At:         now,
	}
	s.state.Events = append(s.state.Events, ev)
	return ev
}

// replayRevokeLocked 处理重放：记录重放事件、撤销家族，并把受影响的
// 后续令牌（世代大于被重放令牌且尚未消费的令牌）标记到该重放事件上。
// 此前已合法刷新的链路（已消费的令牌）保持原样。调用方必须持有 s.mu。
func (s *Service) replayRevokeLocked(fam *Family, replayedGeneration int, now time.Time) *Event {
	ev := s.appendEventLocked(EventTypeReplay, fam, replayedGeneration, "replay", now)
	s.revokeLocked(fam, "replay", ev.Seq, now)
	for _, rt := range s.state.RefreshTokens {
		if rt.FamilyID == fam.ID && rt.Generation > replayedGeneration && !rt.Consumed {
			rt.InvalidatedByEvent = ev.Seq
		}
	}
	for _, at := range s.state.AccessTokens {
		if at.FamilyID == fam.ID && at.Generation > replayedGeneration {
			at.InvalidatedByEvent = ev.Seq
		}
	}
	return ev
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
