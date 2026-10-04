package tokenfamilies

import (
	"bytes"
	"errors"
	"log/slog"
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
		Clock:             clock,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestLoginIssuesFirstGeneration(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
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
}

func TestRefreshRotatesAndOldTokenReplayRevokesFamily(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pair2.RefreshToken == pair1.RefreshToken || pair2.AccessToken == pair1.AccessToken {
		t.Fatal("expected rotation to issue a new token pair")
	}
	if pair2.FamilyID != pair1.FamilyID {
		t.Fatal("rotation must stay in the same family")
	}

	// 旧刷新令牌被再次使用：判定重放，撤销整个家族。
	_, err = svc.Refresh(pair1.RefreshToken, "")
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}

	// 家族撤销后，新一代刷新令牌也不可用。
	if _, err := svc.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for new refresh token, got %v", err)
	}
	// 访问令牌校验也必须看到撤销状态。
	if _, err := svc.ValidateAccessToken(pair2.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for access token, got %v", err)
	}
}

func TestRefreshChainAcrossGenerations(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	for i := 0; i < 5; i++ {
		pair, err = svc.Refresh(pair.RefreshToken, "")
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

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	first, err := svc.Refresh(pair1.RefreshToken, "idem-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 网络重试：同一幂等键 + 同一旧令牌，取回相同结果，不触发重放。
	retry, err := svc.Refresh(pair1.RefreshToken, "idem-1")
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if *first != *retry {
		t.Fatal("idempotent retry must return the identical token pair")
	}

	// 同一旧令牌搭配另一个幂等键（或无键）仍是重放。
	if _, err := svc.Refresh(pair1.RefreshToken, "idem-2"); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
}

func TestIdempotencyKeyConflict(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "idem-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 同一幂等键搭配不同的刷新令牌：冲突。
	if _, err := svc.Refresh(pair2.RefreshToken, "idem-1"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestIdempotencyWindowExpires(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := svc.Refresh(pair1.RefreshToken, "idem-1"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 窗口过期后，同一键不再受保护，旧令牌重用按重放处理。
	clock.Advance(6 * time.Minute)
	if _, err := svc.Refresh(pair1.RefreshToken, "idem-1"); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected after window expiry, got %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
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
			pair, err := svc.Refresh(pair1.RefreshToken, "")
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
	if _, err := svc.Refresh(winners[0].RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("family should be revoked after concurrent replay, got %v", err)
	}
}

func TestConcurrentRefreshDistinctFamiliesAllSucceed(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	const n = 8
	pairs := make([]*TokenPair, 0, n)
	for i := 0; i < n; i++ {
		pair, err := svc.Login("user-1", "dev-1")
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
			_, err := svc.Refresh(rt, "")
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
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := svc.RevokeFamily(pair.FamilyID); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if _, err := svc.Refresh(pair.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
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
		svc := newTestService(t, NewMemoryStore(), newFakeClock())
		pair, err := svc.Login("user-1", "dev-1")
		if err != nil {
			t.Fatalf("Login: %v", err)
		}

		var wg sync.WaitGroup
		var refreshPair *TokenPair
		var refreshErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			refreshPair, refreshErr = svc.Refresh(pair.RefreshToken, "")
		}()
		go func() {
			defer wg.Done()
			_ = svc.RevokeFamily(pair.FamilyID)
		}()
		wg.Wait()

		if refreshErr == nil {
			// 刷新先提交：新令牌对随家族一起被撤销，不能使用。
			if _, err := svc.Refresh(refreshPair.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
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

	pair, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	clock.Advance(2 * time.Minute) // 超过访问令牌 TTL（1 分钟）
	if _, err := svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for access token, got %v", err)
	}

	clock.Advance(2 * time.Hour) // 超过刷新令牌 TTL（1 小时）
	if _, err := svc.Refresh(pair.RefreshToken, ""); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for refresh token, got %v", err)
	}
}

func TestInvalidToken(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	if _, err := svc.Refresh("rt_does-not-exist", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.ValidateAccessToken("at_does-not-exist"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.Refresh("", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty token, got %v", err)
	}
}

func TestStatePersistsAcrossServiceRestart(t *testing.T) {
	clock := newFakeClock()
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")

	svc1 := newTestService(t, store, clock)
	pair1, err := svc1.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// 模拟重启：从同一 Store 恢复新服务实例。
	svc2 := newTestService(t, store, clock)
	pair2, err := svc2.Refresh(pair1.RefreshToken, "")
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
	if _, err := svc3.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked after restart, got %v", err)
	}
}

func TestPersistedStateContainsNoPlaintextTokens(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	svc := newTestService(t, store, newFakeClock())

	pair, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := svc.Refresh(pair.RefreshToken, "idem-1"); err != nil {
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

	pair, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := svc.Refresh(pair.RefreshToken, ""); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 触发重放错误，确认错误文本不携带令牌明文。
	_, replayErr := svc.Refresh(pair.RefreshToken, "")
	if replayErr == nil {
		t.Fatal("expected replay error")
	}
	if strings.Contains(replayErr.Error(), pair.RefreshToken) ||
		strings.Contains(replayErr.Error(), pair.AccessToken) {
		t.Fatal("error messages must not contain token values")
	}
}

func TestLoginRequiresDeviceID(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	if _, err := svc.Login("user-1", ""); err == nil {
		t.Fatal("expected error for empty device id")
	}
}

func TestUnbindDeviceRevokesFamily(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if err := svc.UnbindDevice(pair1.FamilyID); err != nil {
		t.Fatalf("UnbindDevice: %v", err)
	}

	// 解绑后刷新链终止：当前刷新令牌与访问令牌都不可用。
	if _, err := svc.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked after unbind, got %v", err)
	}
	if _, err := svc.ValidateAccessToken(pair2.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for access token after unbind, got %v", err)
	}

	// 重复解绑幂等；未知家族报错。
	if err := svc.UnbindDevice(pair1.FamilyID); err != nil {
		t.Fatalf("second unbind should be a no-op: %v", err)
	}
	if err := svc.UnbindDevice("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound, got %v", err)
	}

	// 查询：解绑事件在前、撤销事件在后，撤销原因为 device_unbind。
	view, err := svc.InspectFamily(pair1.FamilyID)
	if err != nil {
		t.Fatalf("InspectFamily: %v", err)
	}
	if !view.Revoked || view.Reason != "device_unbind" {
		t.Fatalf("unexpected view: revoked=%v reason=%q", view.Revoked, view.Reason)
	}
	if view.DeviceID != "" || view.DeviceVersion != 2 {
		t.Fatalf("expected device unbound with version 2, got device=%q version=%d", view.DeviceID, view.DeviceVersion)
	}
	if len(view.Events) != 2 ||
		view.Events[0].Type != EventTypeDeviceUnbind ||
		view.Events[1].Type != EventTypeRevoke {
		t.Fatalf("expected unbind then revoke events, got %+v", view.Events)
	}
	if view.Events[0].Seq >= view.Events[1].Seq {
		t.Fatalf("unbind event must precede revoke event: %+v", view.Events)
	}
	if view.Events[0].DeviceID != "dev-1" {
		t.Fatalf("unbind event must record the unbound device, got %+v", view.Events[0])
	}
	if view.RevokedByEvent != view.Events[1].Seq {
		t.Fatalf("RevokedByEvent must reference the revoke event, got %d", view.RevokedByEvent)
	}
}

func TestUnbindAfterReplayKeepsReasonAndOrdering(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 重放先被发现，家族因 replay 撤销。
	if _, err := svc.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
	// 随后设备解绑：不能恢复已撤销的家族，也不覆盖原撤销原因。
	if err := svc.UnbindDevice(pair1.FamilyID); err != nil {
		t.Fatalf("UnbindDevice: %v", err)
	}

	view, err := svc.InspectFamily(pair1.FamilyID)
	if err != nil {
		t.Fatalf("InspectFamily: %v", err)
	}
	if view.Reason != "replay" {
		t.Fatalf("unbind must not overwrite replay reason, got %q", view.Reason)
	}
	if len(view.Events) != 2 ||
		view.Events[0].Type != EventTypeReplay ||
		view.Events[1].Type != EventTypeDeviceUnbind {
		t.Fatalf("expected replay then unbind events, got %+v", view.Events)
	}
	if view.Events[0].Seq >= view.Events[1].Seq {
		t.Fatalf("replay event must precede unbind event: %+v", view.Events)
	}
	// 旧设备不能恢复已撤销的家族。
	if _, err := svc.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
}

func TestReplayFirstBlocksLaterLegitRefresh(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 重放先被发现。
	if _, err := svc.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
	// 随后到达的合法刷新只能看到撤销原因，不能重新开启新链。
	_, err = svc.Refresh(pair2.RefreshToken, "")
	if !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Fatalf("error must carry the revocation reason, got %v", err)
	}
}

func TestReplayInvalidatesSuccessorsLinkedToEvent(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh gen2: %v", err)
	}
	pair3, err := svc.Refresh(pair2.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh gen3: %v", err)
	}
	// 重放第一代旧令牌：撤销家族，后续令牌定位到该重放事件。
	if _, err := svc.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}

	view, err := svc.InspectFamily(pair1.FamilyID)
	if err != nil {
		t.Fatalf("InspectFamily: %v", err)
	}
	if len(view.Events) != 1 || view.Events[0].Type != EventTypeReplay {
		t.Fatalf("expected exactly one replay event, got %+v", view.Events)
	}
	replaySeq := view.Events[0].Seq
	if view.Events[0].Generation != 1 || view.Events[0].DeviceID != "dev-1" {
		t.Fatalf("replay event must record replayed generation and device, got %+v", view.Events[0])
	}
	if view.RevokedByEvent != replaySeq {
		t.Fatalf("RevokedByEvent must reference the replay event, got %d", view.RevokedByEvent)
	}

	// 此前合法刷新的链路保留：gen1/gen2 已正常消费，不挂在重放事件上。
	byGen := map[int]TokenView{}
	for _, tv := range view.RefreshTokens {
		byGen[tv.Generation] = tv
	}
	if len(byGen) != 3 {
		t.Fatalf("expected 3 refresh token records, got %d", len(byGen))
	}
	if !byGen[1].Consumed || !byGen[2].Consumed {
		t.Fatalf("legitimately rotated tokens must stay consumed: %+v", view.RefreshTokens)
	}
	if byGen[1].InvalidatedByEvent != 0 || byGen[2].InvalidatedByEvent != 0 {
		t.Fatalf("consumed predecessors must not be linked to the replay event: %+v", view.RefreshTokens)
	}
	// 受影响的后续令牌（gen3 未消费）定位到重放事件。
	if byGen[3].Consumed || byGen[3].InvalidatedByEvent != replaySeq {
		t.Fatalf("successor token must be linked to replay event %d: %+v", replaySeq, byGen[3])
	}
	if byGen[3].Digest != digest(pair3.RefreshToken) {
		t.Fatal("view must contain the digest of the successor refresh token")
	}
	// 访问令牌同样定位到重放事件（gen2/gen3 都晚于被重放的 gen1）。
	for _, tv := range view.AccessTokens {
		if tv.Generation > 1 && tv.InvalidatedByEvent != replaySeq {
			t.Fatalf("access token gen %d must be linked to replay event: %+v", tv.Generation, tv)
		}
	}
}

func TestInspectFamilyViewContainsDigestsOnly(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	view, err := svc.InspectFamily(pair1.FamilyID)
	if err != nil {
		t.Fatalf("InspectFamily: %v", err)
	}
	if view.FamilyID != pair1.FamilyID || view.UserID != "user-1" {
		t.Fatalf("unexpected view identity: %+v", view)
	}
	if view.DeviceID != "dev-1" || view.DeviceVersion != 1 || view.Generation != 2 {
		t.Fatalf("unexpected binding/generation: %+v", view)
	}
	if len(view.RefreshTokens) != 2 ||
		view.RefreshTokens[0].Generation != 1 ||
		view.RefreshTokens[1].Generation != 2 {
		t.Fatalf("tokens must be ordered by generation: %+v", view.RefreshTokens)
	}
	if view.RefreshTokens[1].Digest != digest(pair2.RefreshToken) {
		t.Fatal("view must expose token digests")
	}
	// 视图不得包含令牌明文。
	for _, tv := range view.RefreshTokens {
		if tv.Digest == pair1.RefreshToken || tv.Digest == pair2.RefreshToken {
			t.Fatal("view must not contain plaintext tokens")
		}
	}
	if _, err := svc.InspectFamily("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound, got %v", err)
	}
}

func TestConcurrentReplayProducesSingleEvent(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := svc.Refresh(pair1.RefreshToken, ""); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// 旧令牌被并发重放：只允许一个序列结果生效，即恰好一条重放事件。
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Refresh(pair1.RefreshToken, "")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var replaySeen bool
	for err := range errs {
		if errors.Is(err, ErrReplayDetected) {
			replaySeen = true
			continue
		}
		if !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("losing replay requests must observe revocation, got %v", err)
		}
	}
	if !replaySeen {
		t.Fatal("at least one request must observe ErrReplayDetected")
	}

	view, err := svc.InspectFamily(pair1.FamilyID)
	if err != nil {
		t.Fatalf("InspectFamily: %v", err)
	}
	var replayEvents int
	for _, ev := range view.Events {
		if ev.Type == EventTypeReplay {
			replayEvents++
		}
	}
	if replayEvents != 1 {
		t.Fatalf("expected exactly one replay event, got %d", replayEvents)
	}
}

func TestConcurrentRefreshReplayAndUnbind(t *testing.T) {
	// 合法刷新、重放检测与设备解绑并发到达：无论锁的获取顺序如何，
	// 最终家族必然撤销，事件序列完整，旧设备不能恢复家族。
	for i := 0; i < 50; i++ {
		svc := newTestService(t, NewMemoryStore(), newFakeClock())
		pair1, err := svc.Login("user-1", "dev-1")
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		pair2, err := svc.Refresh(pair1.RefreshToken, "")
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}

		var wg sync.WaitGroup
		var legitPair *TokenPair
		var legitErr error
		wg.Add(3)
		go func() { // 合法刷新当前令牌
			defer wg.Done()
			legitPair, legitErr = svc.Refresh(pair2.RefreshToken, "")
		}()
		go func() { // 重放旧令牌
			defer wg.Done()
			_, _ = svc.Refresh(pair1.RefreshToken, "")
		}()
		go func() { // 设备解绑
			defer wg.Done()
			_ = svc.UnbindDevice(pair1.FamilyID)
		}()
		wg.Wait()

		view, err := svc.InspectFamily(pair1.FamilyID)
		if err != nil {
			t.Fatalf("iter %d: InspectFamily: %v", i, err)
		}
		// 重放与解绑都会撤销家族，最终必然处于撤销状态。
		if !view.Revoked {
			t.Fatalf("iter %d: family must end up revoked", i)
		}
		// 事件序号必须是从 1 开始的连续递增序列。
		for j, ev := range view.Events {
			if ev.Seq != int64(j+1) {
				t.Fatalf("iter %d: event seqs must be contiguous, got %+v", i, view.Events)
			}
		}
		var replayEvents int
		for _, ev := range view.Events {
			if ev.Type == EventTypeReplay {
				replayEvents++
			}
		}
		if replayEvents > 1 {
			t.Fatalf("iter %d: at most one replay event, got %d", i, replayEvents)
		}

		if legitErr == nil {
			// 合法刷新先提交：新链随家族一起被撤销，不能继续使用。
			if _, err := svc.Refresh(legitPair.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
				t.Fatalf("iter %d: successor must be revoked, got %v", i, err)
			}
		} else if !errors.Is(legitErr, ErrFamilyRevoked) {
			// 重放或解绑先生效：合法刷新只能看到撤销原因。
			t.Fatalf("iter %d: unexpected legit refresh error %v", i, legitErr)
		}
		// 旧设备不能恢复已撤销的家族：撤销检查先于重放判定。
		if _, err := svc.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("iter %d: old device must not revive the family, got %v", i, err)
		}
	}
}

func TestIdempotentRetryAfterDeviceVersionChangeConflicts(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := svc.Refresh(pair1.RefreshToken, "idem-1"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 设备解绑导致绑定版本变化：窗口内的重试不再返回原结果，而是冲突。
	if err := svc.UnbindDevice(pair1.FamilyID); err != nil {
		t.Fatalf("UnbindDevice: %v", err)
	}
	if _, err := svc.Refresh(pair1.RefreshToken, "idem-1"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict after device version change, got %v", err)
	}
}

func TestDuplicateRefreshSameKeyReturnsOriginalResult(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	first, err := svc.Refresh(pair1.RefreshToken, "idem-dup")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 相同请求重试（同键 + 同令牌 + 设备绑定未变）返回原结果。
	for i := 0; i < 3; i++ {
		retry, err := svc.Refresh(pair1.RefreshToken, "idem-dup")
		if err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
		if *retry != *first {
			t.Fatalf("retry %d must return the original result", i)
		}
	}
}

func TestEventsPersistAcrossRestart(t *testing.T) {
	clock := newFakeClock()
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")

	svc1 := newTestService(t, store, clock)
	pair1, err := svc1.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc1.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := svc1.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}

	// 重启后事件序列、撤销原因与令牌到重放事件的关联仍然可见。
	svc2 := newTestService(t, store, clock)
	view, err := svc2.InspectFamily(pair1.FamilyID)
	if err != nil {
		t.Fatalf("InspectFamily after restart: %v", err)
	}
	if !view.Revoked || view.Reason != "replay" {
		t.Fatalf("unexpected view after restart: %+v", view)
	}
	if len(view.Events) != 1 || view.Events[0].Type != EventTypeReplay {
		t.Fatalf("events must persist across restart: %+v", view.Events)
	}
	for _, tv := range view.RefreshTokens {
		if tv.Generation == 2 && tv.InvalidatedByEvent != view.Events[0].Seq {
			t.Fatalf("successor link to replay event must persist: %+v", tv)
		}
	}
	if _, err := svc2.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked after restart, got %v", err)
	}
}

func TestLogsContainNoTokenValues(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	svc, err := NewService(NewMemoryStore(), Config{
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		IdempotencyWindow: 5 * time.Minute,
		Clock:             newFakeClock(),
		Logger:            logger,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	pair1, err := svc.Login("user-1", "dev-1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	pair2, err := svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 触发重放撤销与设备解绑，覆盖所有日志路径。
	_, _ = svc.Refresh(pair1.RefreshToken, "")
	_ = svc.UnbindDevice(pair1.FamilyID)
	_ = svc.RevokeFamily(pair1.FamilyID)

	logs := buf.String()
	for _, tok := range []string{pair1.AccessToken, pair1.RefreshToken, pair2.AccessToken, pair2.RefreshToken} {
		if strings.Contains(logs, tok) {
			t.Fatalf("logs must not contain token values, found in: %s", logs)
		}
	}
}
