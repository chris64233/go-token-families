package tokenfamilies

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// DeviceIdentity 描述发起请求的设备。
//
// 安全约定：
//   - ID 是设备的稳定标识（由调用方提供，如系统级设备密钥的标识符）；
//   - PublicKey 是设备当前签名密钥的裸公钥（Ed25519，32 字节）；
//   - 服务端只持久化公钥的 SHA-256 摘要（PublicKeyDigest），绝不保存公钥本身；
//     原始公钥与私钥只在单次请求处理期间出现在内存中。
type DeviceIdentity struct {
	ID        string
	PublicKey ed25519.PublicKey
}

// PublicKeyDigest 计算设备公钥的不可逆摘要（SHA-256，十六进制编码）。
// 持久化层只允许保存该摘要。
func PublicKeyDigest(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// validate 校验设备标识与公钥格式是否合法。
func (d DeviceIdentity) validate() error {
	if d.ID == "" {
		return fmt.Errorf("tokenfamilies: device id must not be empty: %w", ErrInvalidDevice)
	}
	if len(d.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("tokenfamilies: device public key must be %d bytes: %w", ed25519.PublicKeySize, ErrInvalidDevice)
	}
	return nil
}

// matches 判断设备身份是否与持久化的绑定记录一致（标识与公钥摘要均相同）。
func (d DeviceIdentity) matches(b DeviceBinding) bool {
	return d.ID == b.DeviceID && PublicKeyDigest(d.PublicKey) == b.PublicKeyDigest
}

// SignedRequest 是所有需要设备签名的请求的公共部分。
type SignedRequest struct {
	// Device 是请求方设备的身份（含本轮出示的裸公钥）。
	Device DeviceIdentity
	// Payload 是被签名的业务内容（规范化由 SignPayload 完成）。
	Payload []byte
	// Signature 是设备私钥对 Payload 的 Ed25519 签名。
	Signature []byte
	// IdempotencyKey 是可选的幂等键；参与签名内容，防止签名被挪用到其它请求。
	IdempotencyKey string
}

// SignPayload 是请求签名的规范化内容。设备侧与服务端必须使用完全一致的拼接，
// 因此该函数同时是验签协议的一部分，签名格式：
//
//	"tf1" 0x00 deviceID 0x00 base64(rawPublicKey) 0x00 payload 0x00 idempotencyKey
//
// 不含任何令牌明文，原始证明材料（公钥/签名）也不进入持久化与日志。
func SignPayload(deviceID string, publicKey ed25519.PublicKey, payload []byte, idempotencyKey string) []byte {
	out := make([]byte, 0, len(deviceID)+ed25519.PublicKeySize+len(payload)+len(idempotencyKey)+16)
	out = append(out, []byte("tf1")...)
	out = append(out, 0)
	out = append(out, []byte(deviceID)...)
	out = append(out, 0)
	out = append(out, publicKey...)
	out = append(out, 0)
	out = append(out, payload...)
	out = append(out, 0)
	out = append(out, []byte(idempotencyKey)...)
	return out
}

// verifySignature 校验设备身份并验签。
// 任何失败都返回不含敏感值的分类错误（ErrInvalidDevice / ErrInvalidSignature）。
func verifySignature(req SignedRequest) error {
	if err := req.Device.validate(); err != nil {
		return err
	}
	if len(req.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("tokenfamilies: signature must be %d bytes: %w", ed25519.SignatureSize, ErrInvalidSignature)
	}
	msg := SignPayload(req.Device.ID, req.Device.PublicKey, req.Payload, req.IdempotencyKey)
	if !ed25519.Verify(req.Device.PublicKey, msg, req.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// RefreshPayload 构造刷新请求的被签名内容：
// 操作标记 + 待轮换刷新令牌摘要 + 设备签名时刻。
// 直接传入刷新令牌明文（函数内部取摘要），设备端与服务端共用同一拼接，
// 令牌明文只用于计算摘要，不进入持久化与日志。
func RefreshPayload(refreshToken string, signedAt time.Time) []byte {
	return []byte(fmt.Sprintf("refresh\x00%s\x00%d", digest(refreshToken), signedAt.UnixNano()))
}

// OldConfirmPayload 构造旧设备确认的被签名内容。
func OldConfirmPayload(challenge, newDeviceID, newPublicKeyDigest string) []byte {
	return []byte("change-old-confirm\x00" + challenge + "\x00" + newDeviceID + "\x00" + newPublicKeyDigest)
}

// NewProofPayload 构造新设备证明的被签名内容。
func NewProofPayload(challenge, oldDeviceID string) []byte {
	return []byte("change-new-proof\x00" + challenge + "\x00" + oldDeviceID)
}

// changeChallenge 是发起更换时服务端生成的随机挑战，参与旧设备确认与新设备证明
// 的签名内容，防止两个签名被预先录制或跨流程重放。
func changeChallenge() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenfamilies: generate change challenge: %w", err)
	}
	return "chg_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
