package tokenfamilies

import "errors"

// 服务对外返回的错误分类。错误信息中绝不包含令牌明文、摘要等敏感值，
// 只允许出现家族 ID 这类不可用于伪造身份的信息。
var (
	// ErrTokenInvalid 表示令牌不存在或格式无法识别。
	ErrTokenInvalid = errors.New("tokenfamilies: token is invalid")
	// ErrTokenExpired 表示令牌已超过有效期。
	ErrTokenExpired = errors.New("tokenfamilies: token is expired")
	// ErrReplayDetected 表示已被消费过的刷新令牌被再次使用，
	// 触发重放检测，所属家族已被整体撤销。
	ErrReplayDetected = errors.New("tokenfamilies: refresh token replay detected, family revoked")
	// ErrFamilyRevoked 表示令牌所属家族已被撤销（主动撤销或重放触发）。
	ErrFamilyRevoked = errors.New("tokenfamilies: token family has been revoked")
	// ErrIdempotencyConflict 表示同一幂等键被用于不同的请求。
	ErrIdempotencyConflict = errors.New("tokenfamilies: idempotency key reused with a different request")
	// ErrFamilyNotFound 表示指定的家族不存在。
	ErrFamilyNotFound = errors.New("tokenfamilies: token family not found")
)
