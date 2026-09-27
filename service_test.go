package tokenfamilies

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var testStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type testEnv struct {
	svc    *Service
	store  *MemoryStore
	clock  *ManualClock
	events []AuditEvent
	mu     sync.Mutex
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := &testEnv{}
	env.store = NewMemoryStore()
	env.clock = NewManualClock(testStart)
	cfg := Config{
		RefreshTTL:        time.Hour,
		AccessTTL:         10 * time.Minute,
		IdempotencyWindow: 30 * time.Second,
	}
	svc, err := NewService(env.store, env.clock, cfg, []byte("test-secret-key-32-bytes-padded!!"), AuditFunc(func(e AuditEvent) {
		env.mu.Lock()
		defer env.mu.Unlock()
		env.events = append(env.events, e)
	}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	env.svc = svc
	return env
}

func (e *testEnv) login(t *testing.T, userID string) TokenPair {
	t.Helper()
	pair, err := e.svc.Login(userID)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return pair
}

func (e *testEnv) auditEvents() []AuditEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]AuditEvent(nil), e.events...)
}

func TestLoginIssuesUsableTokens(t *testing.T) {
	env := newTestEnv(t)
	pair := env.login(t, "user-1")

	if pair.FamilyID == "" || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("login returned incomplete pair: %+v", pair)
	}
	claims, err := env.svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" || claims.FamilyID != pair.FamilyID {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestRefreshRotatesAndInvalidatesOldToken(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")

	pair2, err := env.svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pair2.RefreshToken == pair1.RefreshToken || pair2.AccessToken == pair1.AccessToken {
		t.Fatal("rotation must issue brand-new tokens")
	}
	if pair2.FamilyID != pair1.FamilyID {
		t.Fatal("rotation must stay within the same family")
	}

	// 旧刷新令牌一次性失效，再次使用触发重放。
	if _, err := env.svc.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
}

func TestRefreshChainAdvancesGeneration(t *testing.T) {
	env := newTestEnv(t)
	pair := env.login(t, "user-1")
	for wantGen := 2; wantGen <= 4; wantGen++ {
		next, err := env.svc.Refresh(pair.RefreshToken, "")
		if err != nil {
			t.Fatalf("Refresh to gen %d: %v", wantGen, err)
		}
		pair = next
		fam, ok := env.store.Family(pair.FamilyID)
		if !ok {
			t.Fatal("family missing")
		}
		if fam.Generation != wantGen {
			t.Fatalf("generation = %d, want %d", fam.Generation, wantGen)
		}
	}
}

func TestReplayRevokesWholeFamily(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	pair2, err := env.svc.Refresh(pair1.RefreshToken, "idem-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// 攻击者重放旧令牌（不同的幂等键，即另一个请求）。
	if _, err := env.svc.Refresh(pair1.RefreshToken, "idem-2"); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}

	// 家族内所有刷新令牌都不能再使用。
	if _, err := env.svc.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for successor, got %v", err)
	}
	if _, err := env.svc.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for old token, got %v", err)
	}
	// 幂等重试在家族撤销后同样失败。
	if _, err := env.svc.Refresh(pair1.RefreshToken, "idem-1"); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked for idempotent retry, got %v", err)
	}
	// 访问令牌校验必须看到撤销状态，即使令牌本身未过期。
	if _, err := env.svc.ValidateAccessToken(pair2.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked from access validation, got %v", err)
	}
	if _, err := env.svc.ValidateAccessToken(pair1.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked from access validation, got %v", err)
	}

	fam, _ := env.store.Family(pair1.FamilyID)
	if fam.Status != FamilyStatusRevoked || fam.RevokedReason != RevokeReasonReplay {
		t.Fatalf("family state = %+v, want revoked by replay", fam)
	}
}

func TestIdempotentRetryReturnsSameResult(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")

	first, err := env.svc.Refresh(pair1.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	second, err := env.svc.Refresh(pair1.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if first != second {
		t.Fatalf("idempotent retry returned different result:\nfirst:  %+v\nsecond: %+v", first, second)
	}

	// 幂等命中不应产生新的轮换：家族代数只前进一次。
	fam, _ := env.store.Family(pair1.FamilyID)
	if fam.Generation != 2 {
		t.Fatalf("generation = %d, want 2 (idempotent retry must not rotate again)", fam.Generation)
	}
	// 幂等取回的刷新令牌可以继续正常轮换。
	if _, err := env.svc.Refresh(second.RefreshToken, ""); err != nil {
		t.Fatalf("refresh with idempotently returned token: %v", err)
	}
}

func TestIdempotencyConflict(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	pair2, err := env.svc.Refresh(pair1.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 同一幂等键搭配不同的刷新令牌 → 幂等冲突。
	if _, err := env.svc.Refresh(pair2.RefreshToken, "key-1"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestIdempotencyWindowExpiry(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	pair2, err := env.svc.Refresh(pair1.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	env.clock.Advance(31 * time.Second) // 超过 30s 幂等窗口

	// 窗口过后，同一幂等键可用于不同的新请求，不再构成冲突。
	pair3, err := env.svc.Refresh(pair2.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("refresh after window expiry: %v", err)
	}
	if pair3.RefreshToken == pair2.RefreshToken {
		t.Fatal("expected a new rotation after window expiry")
	}
}

func TestIdempotentRetryAfterWindowBecomesReplay(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	if _, err := env.svc.Refresh(pair1.RefreshToken, "key-1"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	env.clock.Advance(31 * time.Second)

	// 窗口外的迟到重试按新请求处理：旧令牌已消费 → 重放。
	if _, err := env.svc.Refresh(pair1.RefreshToken, "key-1"); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
}

func TestConcurrentRefreshAllowsSingleSuccessor(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")

	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 每个并发请求使用不同的幂等键，模拟不同的客户端请求。
			_, err := env.svc.Refresh(pair1.RefreshToken, fmt.Sprintf("key-%d", i))
			results[i] = err
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrReplayDetected), errors.Is(err, ErrFamilyRevoked):
			// 其余请求必须触发或观察到撤销。
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}

	// 竞争结束后家族必须处于撤销状态（重放触发），且不存在两个有效后继。
	fam, _ := env.store.Family(pair1.FamilyID)
	if fam.Status != FamilyStatusRevoked {
		t.Fatalf("family status = %s, want revoked", fam.Status)
	}
	if got := len(env.store.refreshByDigest); got != 2 {
		t.Fatalf("stored refresh records = %d, want 2 (old + single committed successor)", got)
	}
}

func TestConcurrentIdempotentRetriesShareOneRotation(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")

	const n = 8
	var wg sync.WaitGroup
	pairs := make([]TokenPair, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pairs[i], errs[i] = env.svc.Refresh(pair1.RefreshToken, "same-key")
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("request %d failed: %v", i, errs[i])
		}
		if pairs[i] != pairs[0] {
			t.Fatalf("request %d got a different pair", i)
		}
	}
	fam, _ := env.store.Family(pair1.FamilyID)
	if fam.Generation != 2 || fam.Status != FamilyStatusActive {
		t.Fatalf("family = %+v, want generation 2 and active", fam)
	}
	if got := len(env.store.refreshByDigest); got != 2 {
		t.Fatalf("stored refresh records = %d, want 2", got)
	}
}

func TestRevokeWinsOverPendingRefresh(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")

	if err := env.svc.Revoke(pair1.FamilyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := env.svc.Refresh(pair1.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
	if _, err := env.svc.ValidateAccessToken(pair1.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked from access validation, got %v", err)
	}
	// 重复撤销幂等。
	if err := env.svc.Revoke(pair1.FamilyID); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
}

func TestRevokeRefreshRaceLeavesNoUsableSuccessor(t *testing.T) {
	for i := 0; i < 100; i++ {
		env := newTestEnv(t)
		pair1 := env.login(t, "user-1")

		var wg sync.WaitGroup
		var pair2 TokenPair
		var refreshErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair2, refreshErr = env.svc.Refresh(pair1.RefreshToken, "")
		}()
		revokeErr := env.svc.Revoke(pair1.FamilyID)
		wg.Wait()

		if revokeErr != nil {
			t.Fatalf("Revoke: %v", revokeErr)
		}
		fam, _ := env.store.Family(pair1.FamilyID)
		if fam.Status != FamilyStatusRevoked {
			t.Fatal("family must end up revoked")
		}
		if refreshErr == nil {
			// 刷新即使先提交，撤销之后新令牌也必须全部失效。
			if _, err := env.svc.Refresh(pair2.RefreshToken, ""); !errors.Is(err, ErrFamilyRevoked) {
				t.Fatalf("successor refresh token still usable: %v", err)
			}
			if _, err := env.svc.ValidateAccessToken(pair2.AccessToken); !errors.Is(err, ErrFamilyRevoked) {
				t.Fatalf("successor access token still valid: %v", err)
			}
		} else if !errors.Is(refreshErr, ErrFamilyRevoked) {
			t.Fatalf("unexpected refresh error: %v", refreshErr)
		}
	}
}

func TestExpiredRefreshToken(t *testing.T) {
	env := newTestEnv(t)
	pair := env.login(t, "user-1")

	env.clock.Advance(time.Hour + time.Second) // 超过 RefreshTTL

	if _, err := env.svc.Refresh(pair.RefreshToken, ""); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestExpiredAccessToken(t *testing.T) {
	env := newTestEnv(t)
	pair := env.login(t, "user-1")

	env.clock.Advance(10*time.Minute + time.Second) // 超过 AccessTTL

	if _, err := env.svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestUnknownTokensAreInvalid(t *testing.T) {
	env := newTestEnv(t)
	if _, err := env.svc.Refresh("rt_does-not-exist", ""); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
	if _, err := env.svc.ValidateAccessToken("at_does-not-exist"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
	if err := env.svc.Revoke("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound, got %v", err)
	}
}

func TestAllGenerationsUnusableAfterRevoke(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	pair2, err := env.svc.Refresh(pair1.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	pair3, err := env.svc.Refresh(pair2.RefreshToken, "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if err := env.svc.Revoke(pair1.FamilyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	for i, tok := range []string{pair1.RefreshToken, pair2.RefreshToken, pair3.RefreshToken} {
		if _, err := env.svc.Refresh(tok, ""); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("generation %d token: expected ErrFamilyRevoked, got %v", i+1, err)
		}
	}
}

func TestStorePersistsOnlyDigests(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	pair2, err := env.svc.Refresh(pair1.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	plaintexts := []string{pair1.AccessToken, pair1.RefreshToken, pair2.AccessToken, pair2.RefreshToken}
	var stored []string
	for _, f := range env.store.families {
		stored = append(stored, f.ID, f.UserID)
	}
	for _, r := range env.store.refreshByDigest {
		stored = append(stored, r.Digest, r.FamilyID)
	}
	for _, a := range env.store.accessByDigest {
		stored = append(stored, a.Digest, a.FamilyID)
	}
	for _, idem := range env.store.idemByKey {
		stored = append(stored, idem.Key, idem.RequestFingerprint, idem.RefreshDigest, idem.AccessDigest)
	}
	for _, p := range plaintexts {
		for _, s := range stored {
			if strings.Contains(s, p) {
				t.Fatalf("plaintext token leaked into persistence layer")
			}
		}
	}
}

func TestErrorsAndAuditLogsContainNoSecrets(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	pair2, err := env.svc.Refresh(pair1.RefreshToken, "key-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	errs := []error{}
	_, err = env.svc.Refresh(pair1.RefreshToken, "key-2")
	errs = append(errs, err) // 重放
	_, err = env.svc.Refresh(pair2.RefreshToken, "")
	errs = append(errs, err) // 已撤销
	_, err = env.svc.ValidateAccessToken(pair2.AccessToken)
	errs = append(errs, err) // 已撤销
	_, err = env.svc.Refresh("rt_unknown", "")
	errs = append(errs, err) // 无效

	secrets := []string{pair1.AccessToken, pair1.RefreshToken, pair2.AccessToken, pair2.RefreshToken}
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error message leaks token: %v", err)
			}
		}
	}
	for _, ev := range env.auditEvents() {
		for _, secret := range secrets {
			for _, field := range []string{ev.FamilyID, ev.UserID, ev.Reason, string(ev.Type)} {
				if strings.Contains(field, secret) {
					t.Fatalf("audit event leaks token: %+v", ev)
				}
			}
		}
	}
}

func TestAuditEventsAreEmitted(t *testing.T) {
	env := newTestEnv(t)
	pair1 := env.login(t, "user-1")
	if _, err := env.svc.Refresh(pair1.RefreshToken, "key-1"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := env.svc.Refresh(pair1.RefreshToken, "key-1"); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if _, err := env.svc.Refresh(pair1.RefreshToken, "key-2"); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected replay, got %v", err)
	}

	var types []AuditEventType
	for _, ev := range env.auditEvents() {
		types = append(types, ev.Type)
	}
	want := []AuditEventType{AuditLogin, AuditRefreshRotated, AuditRefreshIdempotent, AuditReplayDetected}
	if len(types) != len(want) {
		t.Fatalf("audit events = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("audit events = %v, want %v", types, want)
		}
	}
}
