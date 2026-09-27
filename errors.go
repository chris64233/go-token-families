package tokenfamilies

import "errors"

// 服务对外暴露的错误分类。调用方应使用 errors.Is 判断。
// 注意：任何错误信息中都不允许包含令牌明文等敏感值，
// 只允许出现家族 ID、过期时刻等非敏感上下文。
var (
	// ErrInvalidToken 表示令牌无法识别（摘要不存在或格式非法）。
	ErrInvalidToken = errors.New("tokenfamilies: invalid token")

	// ErrTokenExpired 表示令牌已超过其过期时间。
	ErrTokenExpired = errors.New("tokenfamilies: token expired")

	// ErrReplayDetected 表示一个已一次性失效的刷新令牌被再次使用，
	// 触发整个令牌家族的撤销。
	ErrReplayDetected = errors.New("tokenfamilies: refresh token replay detected")

	// ErrFamilyRevoked 表示令牌所属家族已被撤销（主动撤销或重放触发）。
	ErrFamilyRevoked = errors.New("tokenfamilies: token family revoked")

	// ErrIdempotencyConflict 表示同一幂等键被用于不同的刷新请求。
	ErrIdempotencyConflict = errors.New("tokenfamilies: idempotency key conflict")

	// ErrFamilyNotFound 表示指定的令牌家族不存在。
	ErrFamilyNotFound = errors.New("tokenfamilies: token family not found")
)
