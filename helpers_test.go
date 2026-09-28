package tokenfamilies

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

func hexEncode(b []byte) string    { return hex.EncodeToString(b) }
func base64RawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// testDevice 持有一台测试设备的身份与私钥。
type testDevice struct {
	id   string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestDevice(t *testing.T, id string) *testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	return &testDevice{id: id, priv: priv, pub: pub}
}

func (d *testDevice) identity() DeviceIdentity {
	return DeviceIdentity{ID: d.id, PublicKey: d.pub}
}

// signRefresh 构造一次由该设备签名的刷新请求。
func (d *testDevice) signRefresh(refreshToken string, at time.Time, idempotencyKey string) RefreshRequest {
	msg := SignPayload(d.id, d.pub, RefreshPayload(refreshToken, at), idempotencyKey)
	sig := ed25519.Sign(d.priv, msg)
	return RefreshRequest{
		RefreshToken:   refreshToken,
		Device:         d.identity(),
		Signature:      sig,
		SignedAt:       at,
		IdempotencyKey: idempotencyKey,
	}
}

// signOldConfirm 对旧设备确认内容签名。
func (d *testDevice) signOldConfirm(challenge, newDeviceID, newKeyDigest string) DeviceSignature {
	msg := SignPayload(d.id, d.pub, OldConfirmPayload(challenge, newDeviceID, newKeyDigest), "")
	return DeviceSignature{Device: d.identity(), Signature: ed25519.Sign(d.priv, msg)}
}

// signNewProof 对新设备证明内容签名。
func (d *testDevice) signNewProof(challenge, oldDeviceID string) DeviceSignature {
	msg := SignPayload(d.id, d.pub, NewProofPayload(challenge, oldDeviceID), "")
	return DeviceSignature{Device: d.identity(), Signature: ed25519.Sign(d.priv, msg)}
}

// mustRefresh 在 t 上执行刷新并要求成功，返回新令牌对。
func mustRefresh(t *testing.T, svc *Service, dev *testDevice, rt string, clock *fakeClock, idem string) *TokenPair {
	t.Helper()
	pair, err := svc.Refresh(dev.signRefresh(rt, clock.Now(), idem))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return pair
}
