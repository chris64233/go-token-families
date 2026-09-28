package tokenfamilies

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// tokenBytes 是令牌随机部分的字节数（256 位）。
const tokenBytes = 32

// newToken 生成一个带前缀的随机不透明令牌，例如 "rt_..."/"at_..."。
// 前缀仅用于人工区分令牌类型，令牌的熵全部来自随机部分。
func newToken(prefix string) (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenfamilies: generate random token: %w", err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// digest 计算令牌的不可逆摘要（SHA-256，十六进制编码）。
// 持久化层只允许保存该摘要，绝不保存令牌明文。
func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// keyDigest 计算设备公钥的不可逆摘要（SHA-256，十六进制编码）。
// 持久化层只保存该摘要，绝不保存公钥本身；公钥与签名只在请求处理
// 过程中短暂出现于内存。
func keyDigest(publicKey []byte) string {
	return KeyDigest(publicKey)
}

// KeyDigest 返回设备公钥的不可逆摘要（SHA-256，十六进制编码）。
// 导出它是因为设备更换的确认签名消息（DeviceChangeConfirmMessage）
// 必须包含新设备公钥摘要，旧设备客户端需要按同一约定计算该值；
// 服务持久化时也只保存该摘要，绝不保存公钥本身。
func KeyDigest(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}
