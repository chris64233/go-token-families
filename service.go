package tokenfamilies

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// Service 提供登录签发、刷新轮换、主动撤销与访问令牌校验能力。
//
// 安全不变量：
//   - 持久化层只保存令牌的 SHA-256 摘要，明文只存在于返回值中；
//   - 携带幂等键的刷新请求，其下一代令牌由服务端密钥经 HMAC 确定性
//     派生，因此窗口内的网络重试可以重算出完全相同的结果，而存储层
//     依然只保存摘要；
//   - 过期与幂等窗口统一使用注入的 Clock 判断；
//   - 错误与审计日志中绝不出现令牌明文或摘要。
type Service struct {
	store  Store
	clock  Clock
	cfg    Config
	secret []byte
	audit  AuditLogger
}

// NewService 创建一个令牌服务。clock 为 nil 时使用系统时钟；
// secret 用于派生幂等请求的令牌，生产环境必须传入稳定的高熵密钥，
// 为 nil 时自动生成随机密钥（进程重启后幂等重试将无法复现原结果）。
func NewService(store Store, clock Clock, cfg Config, secret []byte, audit AuditLogger) (*Service, error) {
	if store == nil {
		return nil, errors.New("tokenfamilies: store is required")
	}
	if clock == nil {
		clock = SystemClock{}
	}
	if cfg.RefreshTTL <= 0 || cfg.AccessTTL <= 0 || cfg.IdempotencyWindow <= 0 {
		return nil, errors.New("tokenfamilies: TTLs and idempotency window must be positive")
	}
	if len(secret) == 0 {
		secret = randomBytes(32)
	}
	if audit == nil {
		audit = AuditFunc(func(AuditEvent) {})
	}
	return &Service{store: store, clock: clock, cfg: cfg, secret: secret, audit: audit}, nil
}

// Login 为用户创建一个新的令牌家族，并签发第一代令牌对。
func (s *Service) Login(userID string) (TokenPair, error) {
	now := s.clock.Now()
	familyID := "fam_" + hex.EncodeToString(randomBytes(16))

	refreshValue := randomToken("rt")
	accessValue := randomToken("at")

	fam := Family{
		ID:         familyID,
		UserID:     userID,
		Status:     FamilyStatusActive,
		Generation: 1,
		CreatedAt:  now,
	}
	refresh := RefreshToken{
		Digest:     digestOf(refreshValue),
		FamilyID:   familyID,
		Generation: 1,
		State:      RefreshStateActive,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.RefreshTTL),
	}
	access := AccessToken{
		Digest:    digestOf(accessValue),
		FamilyID:  familyID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.AccessTTL),
	}
	if err := s.store.CreateFamily(fam, refresh, access); err != nil {
		return TokenPair{}, err
	}
	s.emit(AuditEvent{Time: now, Type: AuditLogin, FamilyID: familyID, UserID: userID, Generation: 1})
	return TokenPair{
		FamilyID:         familyID,
		AccessToken:      accessValue,
		RefreshToken:     refreshValue,
		AccessExpiresAt:  access.ExpiresAt,
		RefreshExpiresAt: refresh.ExpiresAt,
	}, nil
}

// Refresh 用当前刷新令牌轮换出下一代令牌对。旧令牌在轮换提交的
// 瞬间一次性失效；若旧令牌被再次使用则触发重放检测并撤销整个家族。
//
// idempotencyKey 非空时，相同幂等键 + 相同刷新令牌的请求在幂等窗口
// 内返回与首次完全相同的结果；同一幂等键搭配不同令牌则返回
// ErrIdempotencyConflict。
func (s *Service) Refresh(refreshToken, idempotencyKey string) (TokenPair, error) {
	now := s.clock.Now()
	presentedDigest := digestOf(refreshToken)

	cur, ok := s.store.RefreshTokenByDigest(presentedDigest)
	if !ok {
		s.emit(AuditEvent{Time: now, Type: AuditRefreshDenied, Reason: "unknown_token"})
		return TokenPair{}, ErrTokenInvalid
	}
	nextGen := cur.Generation + 1

	var nextRefreshValue, nextAccessValue string
	if idempotencyKey != "" {
		// 确定性派生：重试可重算出相同令牌，存储层仍只保存摘要。
		nextRefreshValue = s.deriveToken("rt", cur.FamilyID, nextGen, idempotencyKey)
		nextAccessValue = s.deriveToken("at", cur.FamilyID, nextGen, idempotencyKey)
	} else {
		nextRefreshValue = randomToken("rt")
		nextAccessValue = randomToken("at")
	}

	attempt := RefreshAttempt{
		PresentedDigest:   presentedDigest,
		IdempotencyKey:    idempotencyKey,
		Now:               now,
		IdempotencyWindow: s.cfg.IdempotencyWindow,
		NextRefresh: RefreshToken{
			Digest:     digestOf(nextRefreshValue),
			FamilyID:   cur.FamilyID,
			Generation: nextGen,
			State:      RefreshStateActive,
			CreatedAt:  now,
			ExpiresAt:  now.Add(s.cfg.RefreshTTL),
		},
		NextAccess: AccessToken{
			Digest:    digestOf(nextAccessValue),
			FamilyID:  cur.FamilyID,
			CreatedAt: now,
			ExpiresAt: now.Add(s.cfg.AccessTTL),
		},
	}
	res, err := s.store.Refresh(attempt)
	if err != nil {
		switch {
		case errors.Is(err, ErrReplayDetected):
			s.emit(AuditEvent{Time: now, Type: AuditReplayDetected, FamilyID: cur.FamilyID, Generation: cur.Generation, Reason: string(RevokeReasonReplay)})
		case errors.Is(err, ErrFamilyRevoked):
			s.emit(AuditEvent{Time: now, Type: AuditRefreshDenied, FamilyID: cur.FamilyID, Generation: cur.Generation, Reason: "family_revoked"})
		case errors.Is(err, ErrTokenExpired):
			s.emit(AuditEvent{Time: now, Type: AuditRefreshDenied, FamilyID: cur.FamilyID, Generation: cur.Generation, Reason: "token_expired"})
		case errors.Is(err, ErrIdempotencyConflict):
			s.emit(AuditEvent{Time: now, Type: AuditRefreshDenied, FamilyID: cur.FamilyID, Generation: cur.Generation, Reason: "idempotency_conflict"})
		}
		return TokenPair{}, err
	}

	eventType := AuditRefreshRotated
	if res.Idempotent {
		eventType = AuditRefreshIdempotent
	}
	s.emit(AuditEvent{Time: now, Type: eventType, FamilyID: res.Family.ID, UserID: res.Family.UserID, Generation: res.Refresh.Generation})
	return TokenPair{
		FamilyID:         res.Family.ID,
		AccessToken:      nextAccessValue,
		RefreshToken:     nextRefreshValue,
		AccessExpiresAt:  res.Access.ExpiresAt,
		RefreshExpiresAt: res.Refresh.ExpiresAt,
	}, nil
}

// Revoke 主动撤销一个令牌家族。撤销与刷新竞争时，撤销优先于尚未
// 提交的新令牌；撤销提交后，该家族所有刷新令牌与访问令牌全部失效。
// 重复撤销是幂等的。
func (s *Service) Revoke(familyID string) error {
	now := s.clock.Now()
	fam, err := s.store.RevokeFamily(familyID, RevokeReasonUser, now)
	if err != nil {
		return err
	}
	s.emit(AuditEvent{Time: now, Type: AuditFamilyRevoked, FamilyID: fam.ID, UserID: fam.UserID, Generation: fam.Generation, Reason: string(fam.RevokedReason)})
	return nil
}

// ValidateAccessToken 校验访问令牌，返回其携带的身份信息。
// 家族一旦被撤销，校验立即失败，即使访问令牌本身尚未过期。
func (s *Service) ValidateAccessToken(accessToken string) (Claims, error) {
	tok, fam, err := s.store.ValidateAccess(digestOf(accessToken), s.clock.Now())
	if err != nil {
		return Claims{}, err
	}
	return Claims{FamilyID: fam.ID, UserID: fam.UserID, ExpiresAt: tok.ExpiresAt}, nil
}

func (s *Service) emit(e AuditEvent) {
	s.audit.LogAudit(e)
}

// deriveToken 用服务端密钥确定性派生令牌，使携带幂等键的请求在
// 重试时可以重算出相同结果，而持久化层无需保存明文。
func (s *Service) deriveToken(kind, familyID string, generation int, idempotencyKey string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(familyID))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.Itoa(generation)))
	mac.Write([]byte{0})
	mac.Write([]byte(idempotencyKey))
	return kind + "_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// digestOf 计算令牌的不可逆摘要，持久化层只保存该值。
func digestOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(kind string) string {
	return kind + "_" + base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("tokenfamilies: crypto/rand unavailable: %v", err))
	}
	return b
}
