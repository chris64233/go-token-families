package tokenfamilies

import "time"

// FamilyStatus 表示令牌家族的生命周期状态。
type FamilyStatus string

const (
	FamilyStatusActive  FamilyStatus = "active"
	FamilyStatusRevoked FamilyStatus = "revoked"
)

// RevokeReason 记录家族被撤销的原因。
type RevokeReason string

const (
	RevokeReasonUser   RevokeReason = "user_revoked"
	RevokeReasonReplay RevokeReason = "replay_detected"
)

// Family 是一次登录建立的令牌家族。家族内所有刷新令牌按代轮换，
// 家族一旦被撤销，其下已签发的所有刷新令牌与访问令牌全部失效。
type Family struct {
	ID            string
	UserID        string
	Status        FamilyStatus
	RevokedReason RevokeReason
	Generation    int
	CreatedAt     time.Time
	RevokedAt     time.Time
}

// RefreshTokenState 表示单枚刷新令牌的状态。
type RefreshTokenState string

const (
	RefreshStateActive   RefreshTokenState = "active"
	RefreshStateConsumed RefreshTokenState = "consumed"
)

// RefreshToken 是刷新令牌的持久化记录。只保存不可逆摘要，绝不保存明文。
type RefreshToken struct {
	Digest     string
	FamilyID   string
	Generation int
	State      RefreshTokenState
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// AccessToken 是访问令牌的持久化记录，只保存不可逆摘要。
// 校验访问令牌时必须同时检查所属家族的撤销状态。
type AccessToken struct {
	Digest    string
	FamilyID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IdempotencyRecord 记录一次已提交的刷新请求，用于在有限窗口内
// 对相同请求（相同幂等键 + 相同请求指纹）返回相同结果。
// 只保存摘要与指纹，不保存任何令牌明文。
type IdempotencyRecord struct {
	Key                string
	FamilyID           string
	RequestFingerprint string // 请求中出示的刷新令牌的摘要
	RefreshDigest      string // 本次签发的新一代刷新令牌摘要
	AccessDigest       string // 本次签发的访问令牌摘要
	ExpiresAt          time.Time
}

// TokenPair 是登录或刷新成功后返回给客户端的令牌对。
// 明文令牌只出现在返回值中，不会写入持久化层。
type TokenPair struct {
	FamilyID         string
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// Claims 是访问令牌校验通过后返回的信息。
type Claims struct {
	FamilyID  string
	UserID    string
	ExpiresAt time.Time
}

// Config 是服务的时限配置。所有时限判断统一使用 Service 注入的时钟。
type Config struct {
	RefreshTTL        time.Duration // 刷新令牌有效期
	AccessTTL         time.Duration // 访问令牌有效期
	IdempotencyWindow time.Duration // 幂等重试窗口
}

// DefaultConfig 返回一组可用的默认时限。
func DefaultConfig() Config {
	return Config{
		RefreshTTL:        30 * 24 * time.Hour,
		AccessTTL:         15 * time.Minute,
		IdempotencyWindow: 30 * time.Second,
	}
}
