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

	// ErrDeviceMismatch 表示请求携带的设备身份（设备标识或公钥摘要）
	// 与家族当前绑定的设备不一致。
	ErrDeviceMismatch = errors.New("tokenfamilies: device binding mismatch")

	// ErrInvalidDeviceProof 表示设备对请求内容的签名无法通过校验。
	ErrInvalidDeviceProof = errors.New("tokenfamilies: invalid device proof")

	// ErrDeviceBindingChanged 表示家族已绑定到新设备：旧设备的迟到请求
	// （包括仍在幂等窗口内的重试）不得再取回任何令牌结果。
	ErrDeviceBindingChanged = errors.New("tokenfamilies: device binding changed")

	// ErrChangeNotFound 表示指定的设备更换流程不存在。
	ErrChangeNotFound = errors.New("tokenfamilies: device change not found")

	// ErrChangeConflict 表示同一更换标识被用于不同内容的更换请求。
	ErrChangeConflict = errors.New("tokenfamilies: device change conflict")

	// ErrChangeExpired 表示设备更换确认流程已过期，需重新发起。
	ErrChangeExpired = errors.New("tokenfamilies: device change expired")

	// ErrChangeCommitted 表示设备更换已完成，后续确认/证明操作无效。
	ErrChangeCommitted = errors.New("tokenfamilies: device change already committed")
)
