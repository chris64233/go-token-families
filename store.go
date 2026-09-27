package tokenfamilies

import (
	"sync"
	"time"
)

// RefreshAttempt 描述一次刷新请求的原子执行上下文。
// NextRefresh / NextAccess 是服务预先生成的候选下一代令牌记录，
// 只有当存储层确认轮换可以提交时才会写入；若家族已被撤销或发生
// 重放，候选记录被直接丢弃，永远不会成为有效令牌。
type RefreshAttempt struct {
	PresentedDigest   string
	IdempotencyKey    string
	Now               time.Time
	IdempotencyWindow time.Duration
	NextRefresh       RefreshToken
	NextAccess        AccessToken
}

// RefreshResult 是一次成功提交（或幂等命中）的刷新结果。
type RefreshResult struct {
	Family     Family
	Refresh    RefreshToken
	Access     AccessToken
	Idempotent bool // true 表示结果来自幂等记录，未发生新的轮换
}

// Store 是令牌家族状态的持久化接口。实现必须保证 Refresh 与
// RevokeFamily 的原子性：同一时刻最多一个刷新轮换能够提交；
// 撤销一旦提交，所有尚未提交的刷新必须观察到撤销状态并失败。
type Store interface {
	// CreateFamily 持久化一个新家族及其第一代令牌。
	CreateFamily(fam Family, refresh RefreshToken, access AccessToken) error
	// Refresh 原子地执行一次刷新：校验出示的令牌、处理幂等、
	// 检测重放并（在允许时）提交下一代令牌。
	Refresh(a RefreshAttempt) (RefreshResult, error)
	// RevokeFamily 撤销一个家族；重复撤销是幂等的。
	RevokeFamily(familyID string, reason RevokeReason, now time.Time) (Family, error)
	// Family 按 ID 读取家族。
	Family(id string) (Family, bool)
	// RefreshTokenByDigest 按摘要读取刷新令牌记录。
	RefreshTokenByDigest(digest string) (RefreshToken, bool)
	// ValidateAccess 校验访问令牌摘要，并检查所属家族的撤销状态。
	ValidateAccess(digest string, now time.Time) (AccessToken, Family, error)
}

// MemoryStore 是 Store 的内存实现，用一把互斥锁保证所有状态变更
// 的原子性，满足轮换、重放检测与撤销竞争的串行化语义。
type MemoryStore struct {
	mu              sync.Mutex
	families        map[string]Family
	refreshByDigest map[string]RefreshToken
	accessByDigest  map[string]AccessToken
	idemByKey       map[string]IdempotencyRecord
}

// NewMemoryStore 创建一个空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		families:        make(map[string]Family),
		refreshByDigest: make(map[string]RefreshToken),
		accessByDigest:  make(map[string]AccessToken),
		idemByKey:       make(map[string]IdempotencyRecord),
	}
}

// CreateFamily 持久化新家族及其第一代令牌。
func (s *MemoryStore) CreateFamily(fam Family, refresh RefreshToken, access AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.families[fam.ID] = fam
	s.refreshByDigest[refresh.Digest] = refresh
	s.accessByDigest[access.Digest] = access
	return nil
}

// Refresh 在单把锁内完成全部判断与提交，保证：
//   - 同一旧令牌的并发刷新最多一个成功，其余触发或观察到撤销；
//   - 撤销一旦先提交，刷新立即失败，候选新令牌被丢弃；
//   - 幂等窗口内的相同请求返回相同结果，窗口外按新请求处理。
func (s *MemoryStore) Refresh(a RefreshAttempt) (RefreshResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.refreshByDigest[a.PresentedDigest]
	if !ok {
		return RefreshResult{}, ErrTokenInvalid
	}
	fam := s.families[rec.FamilyID]

	// 幂等检查优先：相同请求在窗口内直接返回首次的结果。
	if a.IdempotencyKey != "" {
		if idem, ok := s.idemByKey[a.IdempotencyKey]; ok {
			switch {
			case !a.Now.Before(idem.ExpiresAt):
				// 窗口已过，记录失效，按全新请求继续处理。
				delete(s.idemByKey, a.IdempotencyKey)
			case idem.RequestFingerprint != a.PresentedDigest:
				return RefreshResult{}, ErrIdempotencyConflict
			default:
				if fam.Status == FamilyStatusRevoked {
					return RefreshResult{}, ErrFamilyRevoked
				}
				return RefreshResult{
					Family:     fam,
					Refresh:    s.refreshByDigest[idem.RefreshDigest],
					Access:     s.accessByDigest[idem.AccessDigest],
					Idempotent: true,
				}, nil
			}
		}
	}

	// 撤销优先：家族已撤销时，任何刷新都失败，候选新令牌被丢弃。
	if fam.Status == FamilyStatusRevoked {
		return RefreshResult{}, ErrFamilyRevoked
	}
	// 重放检测：已消费的旧令牌被再次使用，撤销整个家族。
	if rec.State == RefreshStateConsumed {
		fam.Status = FamilyStatusRevoked
		fam.RevokedReason = RevokeReasonReplay
		fam.RevokedAt = a.Now
		s.families[fam.ID] = fam
		return RefreshResult{}, ErrReplayDetected
	}
	if !a.Now.Before(rec.ExpiresAt) {
		return RefreshResult{}, ErrTokenExpired
	}

	// 提交轮换：旧令牌一次性失效，写入下一代令牌。
	rec.State = RefreshStateConsumed
	s.refreshByDigest[rec.Digest] = rec

	fam.Generation = a.NextRefresh.Generation
	s.families[fam.ID] = fam
	s.refreshByDigest[a.NextRefresh.Digest] = a.NextRefresh
	s.accessByDigest[a.NextAccess.Digest] = a.NextAccess

	if a.IdempotencyKey != "" {
		s.idemByKey[a.IdempotencyKey] = IdempotencyRecord{
			Key:                a.IdempotencyKey,
			FamilyID:           fam.ID,
			RequestFingerprint: a.PresentedDigest,
			RefreshDigest:      a.NextRefresh.Digest,
			AccessDigest:       a.NextAccess.Digest,
			ExpiresAt:          a.Now.Add(a.IdempotencyWindow),
		}
	}
	return RefreshResult{Family: fam, Refresh: a.NextRefresh, Access: a.NextAccess}, nil
}

// RevokeFamily 撤销指定家族；已撤销的家族重复撤销是幂等的。
func (s *MemoryStore) RevokeFamily(familyID string, reason RevokeReason, now time.Time) (Family, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fam, ok := s.families[familyID]
	if !ok {
		return Family{}, ErrFamilyNotFound
	}
	if fam.Status == FamilyStatusActive {
		fam.Status = FamilyStatusRevoked
		fam.RevokedReason = reason
		fam.RevokedAt = now
		s.families[familyID] = fam
	}
	return fam, nil
}

// Family 按 ID 读取家族。
func (s *MemoryStore) Family(id string) (Family, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fam, ok := s.families[id]
	return fam, ok
}

// RefreshTokenByDigest 按摘要读取刷新令牌记录。
func (s *MemoryStore) RefreshTokenByDigest(digest string) (RefreshToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.refreshByDigest[digest]
	return rec, ok
}

// ValidateAccess 校验访问令牌：记录存在、家族未撤销、且未过期。
func (s *MemoryStore) ValidateAccess(digest string, now time.Time) (AccessToken, Family, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.accessByDigest[digest]
	if !ok {
		return AccessToken{}, Family{}, ErrTokenInvalid
	}
	fam := s.families[tok.FamilyID]
	if fam.Status == FamilyStatusRevoked {
		return AccessToken{}, Family{}, ErrFamilyRevoked
	}
	if !now.Before(tok.ExpiresAt) {
		return AccessToken{}, Family{}, ErrTokenExpired
	}
	return tok, fam, nil
}
