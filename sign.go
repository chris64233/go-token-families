package tokenfamilies

import (
	"crypto/ed25519"
	"fmt"
)

// SignatureVerifier 校验设备对消息的签名。实现只依赖请求中携带的
// 公钥与签名；服务本身不持久化任何公钥、私钥或签名。
type SignatureVerifier interface {
	// Verify 校验 signature 是否为 publicKey 对应私钥对 message 的签名。
	Verify(publicKey, message, signature []byte) bool
}

// ed25519Verifier 是默认的 Ed25519 校验器。
type ed25519Verifier struct{}

// Verify 实现 SignatureVerifier。
func (ed25519Verifier) Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// Ed25519Verifier 返回基于 Ed25519 的签名校验器（Config.Verifier 的默认值）。
func Ed25519Verifier() SignatureVerifier { return ed25519Verifier{} }

// RefreshMessage 构造刷新请求的待签名规范消息。
// 设备私钥应对该消息签名，结果放入 RefreshRequest.Signature。
func RefreshMessage(refreshToken, idempotencyKey string) []byte {
	return []byte("tokenfamilies/refresh/v1\n" + refreshToken + "\n" + idempotencyKey)
}

// DeviceChangeConfirmMessage 构造旧设备确认更换的待签名规范消息。
// nonce 来自 DeviceChangeStatus.Nonce，用于把确认绑定到具体某一次尝试，
// 使旧流程的迟到确认无法影响重新发起的新流程。
func DeviceChangeConfirmMessage(familyID, changeID, nonce, newDeviceID, newKeyDigest string) []byte {
	return []byte(fmt.Sprintf(
		"tokenfamilies/device-change/confirm/v1\n%s\n%s\n%s\n%s\n%s",
		familyID, changeID, nonce, newDeviceID, newKeyDigest,
	))
}

// DeviceChangeProveMessage 构造新设备证明持有私钥的待签名规范消息。
func DeviceChangeProveMessage(familyID, changeID, nonce string) []byte {
	return []byte(fmt.Sprintf(
		"tokenfamilies/device-change/prove/v1\n%s\n%s\n%s",
		familyID, changeID, nonce,
	))
}
