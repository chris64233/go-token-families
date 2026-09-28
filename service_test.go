package tokenfamilies

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock 是可手动推进的测试时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestService(t *testing.T, store Store, clock *fakeClock) *Service {
	t.Helper()
	svc, err := NewService(store, Config{
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		IdempotencyWindow: 5 * time.Minute,
		DeviceChangeTTL:   5 * time.Minute,
		Clock:             clock,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// testDevice 是测试用的设备身份（Ed25519 密钥对）。
type testDevice struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestDevice(t *testing.T, id string) *testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	return &testDevice{id: id, pub: pub, priv: priv}
}

// refreshReq 构造携带有效设备签名的刷新请求。
func (d *testDevice) refreshReq(token, idemKey string) RefreshRequest {
	return RefreshRequest{
		RefreshToken:    token,
		IdempotencyKey:  idemKey,
		DeviceID:        d.id,
		DevicePublicKey: d.pub,
		Signature:       ed25519.Sign(d.priv, RefreshMessage(token, idemKey)),
	}
}

// login 以指定设备登录并返回第一代令牌对。
func login(t *testing.T, svc *Service, userID string, dev *testDevice) *TokenPair {
	t.Helper()
	pair, err := svc.Login(userID, dev.id, dev.pub)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return pair
}

func TestLoginIssuesFirstGeneration(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair := login(t, svc, "user-1", dev)
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected non-empty token pair")
	}
	if pair.FamilyID == "" {
		t.Fatal("expected family id")
	}

	claims, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" || claims.FamilyID != pair.FamilyID {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.DeviceID != "dev-1" || claims.BindingVersion != 1 {
		t.Fatalf("claims must reflect device binding: %+v", claims)
	}
}

func TestRefreshRotatesAndOldTokenReplayRevokesFamily(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair1 := login(t, svc, "user-1", dev)
	pair2, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, ""))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pair2.RefreshToken == pair1.RefreshToken || pair2.AccessToken == pair1.AccessToken {
		t.Fatal("expected rotation to issue a new token pair")
	}
	if pair2.FamilyID != pair1.FamilyID {
		t.Fatal("rotation must stay in the same family")
	}

	// 旧刷新令牌被再次使用（设备证明有效）：判定重放，撤销整个家族。
	_, err = svc.Refresh(dev.refreshReq(pair1.RefreshToken, ""))
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}

	// 家族撤销后，新一代刷新令牌也不可用。
	if _, err := svc.Refresh(dev.refreshReq(pair2.RefreshToken, "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for new refresh token, got %v", err)
	}
	// 访问令牌校验也必须看到撤销状态。
	if _, err := svc.ValidateAccessToken(pair2.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for access token, got %v", err)
	}
}

func TestRefreshChainAcrossGenerations(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair := login(t, svc, "user-1", dev)
	for i := 0; i < 5; i++ {
		var err error
		pair, err = svc.Refresh(dev.refreshReq(pair.RefreshToken, ""))
		if err != nil {
			t.Fatalf("refresh generation %d: %v", i+2, err)
		}
	}
	if _, err := svc.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("latest access token should be valid: %v", err)
	}
}

func TestIdempotentRetryReturnsSameResult(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair1 := login(t, svc, "user-1", dev)
	first, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, "idem-1"))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 网络重试：同一幂等键 + 同一旧令牌，取回相同结果，不触发重放。
	retry, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, "idem-1"))
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if *first != *retry {
		t.Fatal("idempotent retry must return the identical token pair")
	}

	// 同一旧令牌搭配另一个幂等键（或无键）仍是重放。
	if _, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, "idem-2")); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
}

func TestIdempotencyKeyConflict(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair1 := login(t, svc, "user-1", dev)
	pair2, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, "idem-1"))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 同一幂等键搭配不同的刷新令牌：冲突。
	if _, err := svc.Refresh(dev.refreshReq(pair2.RefreshToken, "idem-1")); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestIdempotencyWindowExpires(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "dev-1")

	pair1 := login(t, svc, "user-1", dev)
	if _, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, "idem-1")); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 窗口过期后，同一键不再受保护，旧令牌重用按重放处理。
	clock.Advance(6 * time.Minute)
	if _, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, "idem-1")); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected after window expiry, got %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair1 := login(t, svc, "user-1", dev)

	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	pairs := make(chan *TokenPair, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, err := svc.Refresh(dev.refreshReq(pair1.RefreshToken, ""))
			if err != nil {
				results <- err
				return
			}
			pairs <- pair
		}()
	}
	wg.Wait()
	close(results)
	close(pairs)

	var winners []*TokenPair
	for pair := range pairs {
		winners = append(winners, pair)
	}
	if len(winners) != 1 {
		t.Fatalf("expected exactly one successful rotation, got %d", len(winners))
	}
	for err := range results {
		if !errors.Is(err, ErrReplayDetected) && !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("losing requests must observe replay/revocation, got %v", err)
		}
	}

	// 只能存在一个有效后继：胜者的刷新令牌可用，但家族已因重放被撤销。
	// 因此先验证撤销状态对所有人生效，再单独验证“唯一后继”语义。
	if _, err := svc.Refresh(dev.refreshReq(winners[0].RefreshToken, "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("family should be revoked after concurrent replay, got %v", err)
	}
}

func TestConcurrentRefreshDistinctFamiliesAllSucceed(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	const n = 8
	devs := make([]*testDevice, 0, n)
	pairs := make([]*TokenPair, 0, n)
	for i := 0; i < n; i++ {
		dev := newTestDevice(t, "dev-1")
		pair := login(t, svc, "user-1", dev)
		devs = append(devs, dev)
		pairs = append(pairs, pair)
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i, pair := range pairs {
		wg.Add(1)
		go func(dev *testDevice, rt string) {
			defer wg.Done()
			_, err := svc.Refresh(dev.refreshReq(rt, ""))
			errs <- err
		}(devs[i], pair.RefreshToken)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("independent families must not interfere: %v", err)
		}
	}
}

func TestRevokeWinsOverRefresh(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair := login(t, svc, "user-1", dev)
	if err := svc.RevokeFamily(pair.FamilyID); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if _, err := svc.Refresh(dev.refreshReq(pair.RefreshToken, "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
	if _, err := svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for access token, got %v", err)
	}
	// 重复撤销是幂等的。
	if err := svc.RevokeFamily(pair.FamilyID); err != nil {
		t.Fatalf("second revoke should be a no-op: %v", err)
	}
	if err := svc.RevokeFamily("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound, got %v", err)
	}
}

func TestConcurrentRevokeAndRefresh(t *testing.T) {
	// 无论竞争结果如何，最终家族必须处于撤销状态，
	// 且不可能出现“撤销后仍签发出有效新令牌”的情况。
	for i := 0; i < 50; i++ {
		svc := newTestService(t, NewMemoryStore(), newFakeClock())
		dev := newTestDevice(t, "dev-1")
		pair := login(t, svc, "user-1", dev)

		var wg sync.WaitGroup
		var refreshPair *TokenPair
		var refreshErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			refreshPair, refreshErr = svc.Refresh(dev.refreshReq(pair.RefreshToken, ""))
		}()
		go func() {
			defer wg.Done()
			_ = svc.RevokeFamily(pair.FamilyID)
		}()
		wg.Wait()

		if refreshErr == nil {
			// 刷新先提交：新令牌对随家族一起被撤销，不能使用。
			if _, err := svc.Refresh(dev.refreshReq(refreshPair.RefreshToken, "")); !errors.Is(err, ErrFamilyRevoked) {
				t.Fatalf("iter %d: successor refresh token must be revoked, got %v", i, err)
			}
			if _, err := svc.ValidateAccessToken(refreshPair.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
				t.Fatalf("iter %d: successor access token must be revoked, got %v", i, err)
			}
		} else if !errors.Is(refreshErr, ErrFamilyRevoked) {
			t.Fatalf("iter %d: unexpected refresh error %v", i, refreshErr)
		}
	}
}

func TestExpiryUsesUnifiedClock(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "dev-1")

	pair := login(t, svc, "user-1", dev)

	clock.Advance(2 * time.Minute) // 超过访问令牌 TTL（1 分钟）
	if _, err := svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for access token, got %v", err)
	}

	clock.Advance(2 * time.Hour) // 超过刷新令牌 TTL（1 小时）
	if _, err := svc.Refresh(dev.refreshReq(pair.RefreshToken, "")); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for refresh token, got %v", err)
	}
}

func TestInvalidToken(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	if _, err := svc.Refresh(dev.refreshReq("rt_does-not-exist", "")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.ValidateAccessToken("at_does-not-exist"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.Refresh(dev.refreshReq("", "")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty token, got %v", err)
	}
}

func TestStatePersistsAcrossServiceRestart(t *testing.T) {
	clock := newFakeClock()
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	dev := newTestDevice(t, "dev-1")

	svc1 := newTestService(t, store, clock)
	pair1 := login(t, svc1, "user-1", dev)

	// 模拟重启：从同一 Store 恢复新服务实例。
	svc2 := newTestService(t, store, clock)
	pair2, err := svc2.Refresh(dev.refreshReq(pair1.RefreshToken, ""))
	if err != nil {
		t.Fatalf("Refresh after restart: %v", err)
	}
	if _, err := svc2.ValidateAccessToken(pair2.AccessToken); err != nil {
		t.Fatalf("ValidateAccessToken after restart: %v", err)
	}
	if err := svc2.RevokeFamily(pair1.FamilyID); err != nil {
		t.Fatalf("RevokeFamily after restart: %v", err)
	}

	// 再次重启后撤销状态仍然可见。
	svc3 := newTestService(t, store, clock)
	if _, err := svc3.Refresh(dev.refreshReq(pair2.RefreshToken, "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked after restart, got %v", err)
	}
}

func TestPersistedStateContainsNoPlaintextTokens(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	svc := newTestService(t, store, newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair := login(t, svc, "user-1", dev)
	if _, err := svc.Refresh(dev.refreshReq(pair.RefreshToken, "idem-1")); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	content := string(data)
	if strings.Contains(content, pair.AccessToken) || strings.Contains(content, pair.RefreshToken) {
		t.Fatal("persisted state must not contain plaintext tokens")
	}
	if strings.Contains(content, "\"at_") || strings.Contains(content, "\"rt_") {
		t.Fatal("persisted state must only contain token digests")
	}
}

func TestErrorsAndLogsContainNoTokenValues(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")

	pair := login(t, svc, "user-1", dev)
	if _, err := svc.Refresh(dev.refreshReq(pair.RefreshToken, "")); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 触发重放错误，确认错误文本不携带令牌明文。
	_, replayErr := svc.Refresh(dev.refreshReq(pair.RefreshToken, ""))
	if replayErr == nil {
		t.Fatal("expected replay error")
	}
	if strings.Contains(replayErr.Error(), pair.RefreshToken) ||
		strings.Contains(replayErr.Error(), pair.AccessToken) {
		t.Fatal("error messages must not contain token values")
	}
}
