package tokenfamilies

import "errors"

// 服务对外暴露的错误分类。调用方应使用 errors.Is 判断。
// 注意：任何错误信息中都不允许包含令牌明文、私钥/公钥、签名或原始证明材料，
// 只允许出现家族 ID、更换流程 ID、过期时刻等非敏感上下文。
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

	// ErrInvalidDevice 表示设备标识或公钥格式非法。
	ErrInvalidDevice = errors.New("tokenfamilies: invalid device identity")

	// ErrDeviceMismatch 表示请求签名方不是家族当前绑定的设备
	//（设备标识或公钥摘要不匹配）。旧设备在更换完成后再请求会落入此类。
	ErrDeviceMismatch = errors.New("tokenfamilies: device not bound to family")

	// ErrInvalidSignature 表示签名缺失、格式非法、签名内容与请求不一致
	// 或签名验签失败。
	ErrInvalidSignature = errors.New("tokenfamilies: invalid request signature")

	// ErrDeviceBindingChanged 表示令牌签发时的设备绑定版本已过期
	//（家族已切换到其他设备）。访问令牌校验与旧刷新令牌的迟到重试
	// 都会返回该错误；它不会触发家族撤销。
	ErrDeviceBindingChanged = errors.New("tokenfamilies: device binding version changed")

	// ErrChangeNotFound 表示设备更换流程不存在。
	ErrChangeNotFound = errors.New("tokenfamilies: device change flow not found")

	// ErrChangeExpired 表示设备更换流程已超过其短期有效期。
	ErrChangeExpired = errors.New("tokenfamilies: device change flow expired")

	// ErrChangeConflict 表示同一更换事件 ID 被用于不同的更换内容。
	ErrChangeConflict = errors.New("tokenfamilies: device change event conflict")

	// ErrChangeInProgress 表示家族已有一个尚未过期的更换流程，
	// 必须先完成或等待其过期后才能发起新的流程。
	ErrChangeInProgress = errors.New("tokenfamilies: device change already in progress")
)
