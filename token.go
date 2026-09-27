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
