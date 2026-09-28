package tokenfamilies

import (
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
		AccessTokenTTL:     time.Minute,
		RefreshTokenTTL:    time.Hour,
		IdempotencyWindow:  5 * time.Minute,
		DeviceChangeTTL:    10 * time.Minute,
		SignatureFreshness: time.Minute,
		Clock:              clock,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestLoginIssuesFirstGeneration(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "device-1")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected non-empty token pair")
	}
	if pair.FamilyID == "" {
		t.Fatal("expected family id")
	}
	if pair.BindingVersion != 1 {
		t.Fatalf("expected first binding version 1, got %d", pair.BindingVersion)
	}

	claims, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" || claims.FamilyID != pair.FamilyID {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.DeviceID != "device-1" || claims.BindingVersion != 1 {
		t.Fatalf("claims must reflect current device binding: %+v", claims)
	}
}

func TestLoginRejectsInvalidDevice(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "device-1")

	bad := dev.identity()
	bad.PublicKey = nil
	if _, err := svc.Login("user-1", bad); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("expected ErrInvalidDevice for missing key, got %v", err)
	}
	bad2 := DeviceIdentity{ID: "", PublicKey: dev.pub}
	if _, err := svc.Login("user-1", bad2); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("expected ErrInvalidDevice for empty id, got %v", err)
	}
}

func TestRefreshRotatesAndOldTokenReplayRevokesFamily(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair1, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2 := mustRefresh(t, svc, dev, pair1.RefreshToken, clock, "")
	if pair2.RefreshToken == pair1.RefreshToken || pair2.AccessToken == pair1.AccessToken {
		t.Fatal("expected rotation to issue a new token pair")
	}
	if pair2.FamilyID != pair1.FamilyID {
		t.Fatal("rotation must stay in the same family")
	}

	// 旧刷新令牌被当前绑定设备再次使用：判定重放，撤销整个家族。
	_, err = svc.Refresh(dev.signRefresh(pair1.RefreshToken, clock.Now(), ""))
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}

	// 家族撤销后，新一代刷新令牌也不可用。
	if _, err := svc.Refresh(dev.signRefresh(pair2.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for new refresh token, got %v", err)
	}
	// 访问令牌校验也必须看到撤销状态。
	if _, err := svc.ValidateAccessToken(pair2.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for access token, got %v", err)
	}
}

func TestRefreshChainAcrossGenerations(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	for i := 0; i < 5; i++ {
		pair = mustRefresh(t, svc, dev, pair.RefreshToken, clock, "")
	}
	if _, err := svc.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("latest access token should be valid: %v", err)
	}
}

func TestRefreshRequiresBoundDeviceSignature(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")
	other := newTestDevice(t, "device-2")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// 另一台设备持有刷新令牌也无法刷新：设备不匹配。
	_, err = svc.Refresh(other.signRefresh(pair.RefreshToken, clock.Now(), ""))
	if !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch, got %v", err)
	}

	// 本设备但篡改签名内容（错误的幂等键）：验签失败。
	req := dev.signRefresh(pair.RefreshToken, clock.Now(), "key-a")
	req.IdempotencyKey = "key-b"
	if _, err := svc.Refresh(req); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered request, got %v", err)
	}

	// 签名时刻超出新鲜度窗口：拒绝。
	if _, err := svc.Refresh(dev.signRefresh(pair.RefreshToken, clock.Now().Add(-2*time.Minute), "")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for stale signature, got %v", err)
	}

	// 正确签名仍可刷新。
	mustRefresh(t, svc, dev, pair.RefreshToken, clock, "")
}

func TestIdempotentRetryReturnsSameResult(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair1, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	first := mustRefresh(t, svc, dev, pair1.RefreshToken, clock, "idem-1")
	// 网络重试：同一幂等键 + 同一旧令牌，取回相同结果，不触发重放。
	retry, err := svc.Refresh(dev.signRefresh(pair1.RefreshToken, clock.Now(), "idem-1"))
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if *first != *retry {
		t.Fatal("idempotent retry must return the identical token pair")
	}

	// 同一旧令牌搭配另一个幂等键（或无键）仍是重放。
	if _, err := svc.Refresh(dev.signRefresh(pair1.RefreshToken, clock.Now(), "idem-2")); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
}

func TestIdempotencyKeyConflict(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair1, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2 := mustRefresh(t, svc, dev, pair1.RefreshToken, clock, "idem-1")
	// 同一幂等键搭配不同的刷新令牌：冲突。
	if _, err := svc.Refresh(dev.signRefresh(pair2.RefreshToken, clock.Now(), "idem-1")); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestIdempotencyWindowExpires(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair1, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	mustRefresh(t, svc, dev, pair1.RefreshToken, clock, "idem-1")
	// 窗口过期后，同一键不再受保护，旧令牌重用按重放处理。
	clock.Advance(6 * time.Minute)
	if _, err := svc.Refresh(dev.signRefresh(pair1.RefreshToken, clock.Now(), "idem-1")); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected after window expiry, got %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair1, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	pairs := make(chan *TokenPair, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, err := svc.Refresh(dev.signRefresh(pair1.RefreshToken, clock.Now(), ""))
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

	// 家族已因并发重放被撤销：胜者的刷新令牌同样不可用。
	if _, err := svc.Refresh(dev.signRefresh(winners[0].RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("family should be revoked after concurrent replay, got %v", err)
	}
}

func TestConcurrentRefreshDistinctFamiliesAllSucceed(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	const n = 8
	pairs := make([]*TokenPair, 0, n)
	for i := 0; i < n; i++ {
		pair, err := svc.Login("user-1", dev.identity())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		pairs = append(pairs, pair)
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, pair := range pairs {
		wg.Add(1)
		go func(rt string) {
			defer wg.Done()
			_, err := svc.Refresh(dev.signRefresh(rt, clock.Now(), ""))
			errs <- err
		}(pair.RefreshToken)
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
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := svc.RevokeFamily(pair.FamilyID); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if _, err := svc.Refresh(dev.signRefresh(pair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
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
	// 且不可能出现“撤销后仍签发有效新令牌”的情况。
	for i := 0; i < 50; i++ {
		clock := newFakeClock()
		svc := newTestService(t, NewMemoryStore(), clock)
		dev := newTestDevice(t, "device-1")
		pair, err := svc.Login("user-1", dev.identity())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}

		var wg sync.WaitGroup
		var refreshPair *TokenPair
		var refreshErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			refreshPair, refreshErr = svc.Refresh(dev.signRefresh(pair.RefreshToken, clock.Now(), ""))
		}()
		go func() {
			defer wg.Done()
			_ = svc.RevokeFamily(pair.FamilyID)
		}()
		wg.Wait()

		if refreshErr == nil {
			// 刷新先提交：新令牌对随家族一起被撤销，不能使用。
			if _, err := svc.Refresh(dev.signRefresh(refreshPair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
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
	dev := newTestDevice(t, "device-1")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	clock.Advance(2 * time.Minute) // 超过访问令牌 TTL（1 分钟）
	if _, err := svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for access token, got %v", err)
	}

	clock.Advance(2 * time.Hour) // 超过刷新令牌 TTL（1 小时）
	// 刷新签名新鲜度为 1 分钟：设备侧按当前时钟重签，只应观察到令牌过期。
	if _, err := svc.Refresh(dev.signRefresh(pair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for refresh token, got %v", err)
	}
}

func TestInvalidToken(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	if _, err := svc.Refresh(dev.signRefresh("rt_does-not-exist", clock.Now(), "")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.ValidateAccessToken("at_does-not-exist"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.Refresh(RefreshRequest{Device: dev.identity(), SignedAt: clock.Now()}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty token, got %v", err)
	}
}

func TestStatePersistsAcrossServiceRestart(t *testing.T) {
	clock := newFakeClock()
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")

	svc1 := newTestService(t, store, clock)
	dev := newTestDevice(t, "device-1")
	pair1, err := svc1.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// 模拟重启：从同一 Store 恢复新服务实例。
	svc2 := newTestService(t, store, clock)
	pair2 := mustRefresh(t, svc2, dev, pair1.RefreshToken, clock, "")
	if _, err := svc2.ValidateAccessToken(pair2.AccessToken); err != nil {
		t.Fatalf("ValidateAccessToken after restart: %v", err)
	}
	if err := svc2.RevokeFamily(pair1.FamilyID); err != nil {
		t.Fatalf("RevokeFamily after restart: %v", err)
	}

	// 再次重启后撤销状态仍然可见。
	svc3 := newTestService(t, store, clock)
	if _, err := svc3.Refresh(dev.signRefresh(pair2.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked after restart, got %v", err)
	}
}

func TestPersistedStateContainsNoPlaintextTokens(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	clock := newFakeClock()
	svc := newTestService(t, store, clock)
	dev := newTestDevice(t, "device-1")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	mustRefresh(t, svc, dev, pair.RefreshToken, clock, "idem-1")

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
	// 公钥本身不得落盘：裸公钥的任何编码形式都不应出现（hex 与 base64 两种）。
	if strings.Contains(content, hexEncode(dev.pub)) {
		t.Fatal("persisted state must not contain raw device public key (hex)")
	}
	if strings.Contains(content, base64RawURL(dev.pub)) {
		t.Fatal("persisted state must not contain raw device public key (base64)")
	}
	// 公钥摘要可以出现，且不等于公钥本身。
	if !strings.Contains(content, PublicKeyDigest(dev.pub)) {
		t.Fatal("persisted state should contain public key digest")
	}
}

func TestErrorsAndLogsContainNoTokenValues(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	dev := newTestDevice(t, "device-1")

	pair, err := svc.Login("user-1", dev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	mustRefresh(t, svc, dev, pair.RefreshToken, clock, "")
	// 触发重放错误，确认错误文本不携带令牌明文。
	_, replayErr := svc.Refresh(dev.signRefresh(pair.RefreshToken, clock.Now(), ""))
	if replayErr == nil {
		t.Fatal("expected replay error")
	}
	if strings.Contains(replayErr.Error(), pair.RefreshToken) ||
		strings.Contains(replayErr.Error(), pair.AccessToken) {
		t.Fatal("error messages must not contain token values")
	}
}
