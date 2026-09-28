package tokenfamilies

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// initiateChange 发起设备更换并要求成功，返回流程状态（含挑战）。
func initiateChange(t *testing.T, svc *Service, accessToken, eventID string, newDev *testDevice) *DeviceChangeStatus {
	t.Helper()
	st, err := svc.InitiateDeviceChange(accessToken, eventID, newDev.identity())
	if err != nil {
		t.Fatalf("InitiateDeviceChange: %v", err)
	}
	if st.Status != StatusPending || st.Challenge == "" {
		t.Fatalf("expected pending change with challenge, got %+v", st)
	}
	return st
}

// completeChangeWith 按"旧确认 -> 新证明"的顺序完成更换，返回最后一步结果。
func completeChangeWith(t *testing.T, svc *Service, st *DeviceChangeStatus, oldDev, newDev *testDevice) *DeviceChangeStepResult {
	t.Helper()
	oldRes, err := svc.ConfirmDeviceChange(st.ID, oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub)))
	if err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	if oldRes.TokenPair != nil {
		t.Fatal("old confirmation alone must not deliver a token pair")
	}
	if !oldRes.Status.OldConfirmed || oldRes.Status.NewProved {
		t.Fatalf("unexpected status after old confirm: %+v", oldRes.Status)
	}
	newRes, err := svc.ProvideNewDeviceProof(st.ID, newDev.signNewProof(st.Challenge, st.OldDeviceID))
	if err != nil {
		t.Fatalf("ProvideNewDeviceProof: %v", err)
	}
	if newRes.TokenPair == nil {
		t.Fatal("completing step must deliver the new token pair exactly once")
	}
	if !newRes.Status.NewProved || newRes.Status.Status != StatusCompleted {
		t.Fatalf("unexpected status after new proof: %+v", newRes.Status)
	}
	return newRes
}

func TestDeviceChangeHappyPathAtomicallyRebinds(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// 换绑前先做一次普通轮换，得到一个 v1 下的有效刷新令牌。
	pair = mustRefresh(t, svc, oldDev, pair.RefreshToken, clock, "")

	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)
	if st.BindingVersion != 1 || st.OldDeviceID != "device-old" || st.NewDeviceID != "device-new" {
		t.Fatalf("unexpected change status: %+v", st)
	}

	res := completeChangeWith(t, svc, st, oldDev, newDev)
	newPair := res.TokenPair
	if newPair.FamilyID != pair.FamilyID {
		t.Fatal("new pair must stay in the same family")
	}
	if newPair.BindingVersion != 2 {
		t.Fatalf("expected new pair bound at version 2, got %d", newPair.BindingVersion)
	}
	if newPair.RefreshToken == pair.RefreshToken || newPair.AccessToken == pair.AccessToken {
		t.Fatal("device change must rotate tokens")
	}

	// 家族当前绑定已切换。
	info, err := svc.GetFamilyBinding(pair.FamilyID)
	if err != nil {
		t.Fatalf("GetFamilyBinding: %v", err)
	}
	if info.DeviceID != "device-new" || info.BindingVersion != 2 {
		t.Fatalf("family binding not switched: %+v", info)
	}

	// 新设备可刷新；旧设备立即失去刷新资格。
	next := mustRefresh(t, svc, newDev, newPair.RefreshToken, clock, "")
	if next.BindingVersion != 2 {
		t.Fatalf("expected refresh at binding version 2, got %d", next.BindingVersion)
	}
	if _, err := svc.Refresh(oldDev.signRefresh(pair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("old device must lose refresh eligibility, got %v", err)
	}

	// 旧访问令牌校验反映版本变更；新访问令牌正常。
	if _, err := svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrDeviceBindingChanged) {
		t.Fatalf("old access token must fail with binding changed, got %v", err)
	}
	claims, err := svc.ValidateAccessToken(newPair.AccessToken)
	if err != nil {
		t.Fatalf("new access token should validate: %v", err)
	}
	if claims.DeviceID != "device-new" || claims.BindingVersion != 2 {
		t.Fatalf("claims must reflect new binding: %+v", claims)
	}

	// 换绑时旧刷新令牌被标记为 device_change 消耗（而不是重放）。
	oldRec := svc.state.RefreshTokens[digest(pair.RefreshToken)]
	if !oldRec.Consumed || oldRec.ConsumeReason != consumeReasonDeviceChange {
		t.Fatalf("old refresh token must be consumed by device change: %+v", oldRec)
	}
}

func TestDeviceChangeStepsWorkInEitherOrder(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)

	// 先提交新设备证明，再提交旧设备确认，最后一步完成。
	newRes, err := svc.ProvideNewDeviceProof(st.ID, newDev.signNewProof(st.Challenge, st.OldDeviceID))
	if err != nil {
		t.Fatalf("ProvideNewDeviceProof: %v", err)
	}
	if newRes.TokenPair != nil || newRes.Status.NewProved != true {
		t.Fatalf("new proof alone must not complete: %+v", newRes)
	}
	oldRes, err := svc.ConfirmDeviceChange(st.ID, oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub)))
	if err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	if oldRes.TokenPair == nil || oldRes.TokenPair.BindingVersion != 2 {
		t.Fatalf("expected completion pair at v2, got %+v", oldRes.TokenPair)
	}
}

func TestDeviceChangeNewPairDeliveredExactlyOnce(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)
	res := completeChangeWith(t, svc, st, oldDev, newDev)
	delivered := res.TokenPair.RefreshToken

	// 已完成流程上重放任意一方签名：返回完成状态，但绝不再次交付令牌。
	replayOld, err := svc.ConfirmDeviceChange(st.ID, oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub)))
	if err != nil {
		t.Fatalf("replayed confirm: %v", err)
	}
	if replayOld.TokenPair != nil || replayOld.Status.Status != StatusCompleted {
		t.Fatalf("replayed confirm must not redeliver pair: %+v", replayOld)
	}
	replayNew, err := svc.ProvideNewDeviceProof(st.ID, newDev.signNewProof(st.Challenge, st.OldDeviceID))
	if err != nil {
		t.Fatalf("replayed proof: %v", err)
	}
	if replayNew.TokenPair != nil {
		t.Fatal("replayed proof must not redeliver pair")
	}

	// 查询接口同样只回状态。
	got, err := svc.GetDeviceChange(st.ID)
	if err != nil {
		t.Fatalf("GetDeviceChange: %v", err)
	}
	if got.Status != StatusCompleted || got.NewBindingVer != 2 {
		t.Fatalf("unexpected stored status: %+v", got)
	}
	// 已完成流程不再外泄挑战值。
	if got.Challenge != "" {
		t.Fatal("challenge must not be exposed after completion")
	}
	// 交付的新令牌确实可用且只交付过一次：再刷一次即重放链。
	p2 := mustRefresh(t, svc, newDev, delivered, clock, "")
	if p2.RefreshToken == delivered {
		t.Fatal("expected rotation after using delivered token")
	}
}

func TestDeviceChangeRejectsWrongDeviceAndBadSignature(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")
	intruder := newTestDevice(t, "device-old") // 同名设备但持不同密钥

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)

	// 旧确认必须来自登记的旧设备（公钥摘要匹配）。
	if _, err := svc.ConfirmDeviceChange(st.ID, intruder.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub))); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch for wrong old key, got %v", err)
	}
	// 新证明必须来自登记的新设备。
	if _, err := svc.ProvideNewDeviceProof(st.ID, intruder.signNewProof(st.Challenge, st.OldDeviceID)); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch for wrong new device, got %v", err)
	}
	// 身份对、签名错：篡改签名。
	good := oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub))
	good.Signature[0] ^= 0xFF
	if _, err := svc.ConfirmDeviceChange(st.ID, good); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	// 流程仍可正常完成。
	completeChangeWith(t, svc, st, oldDev, newDev)
}

func TestDeviceChangeEventReplayAndConflict(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")
	otherDev := newTestDevice(t, "device-other")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	first := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)

	// 同事件同内容重放：返回同一个待处理流程。
	replay, err := svc.InitiateDeviceChange(pair.AccessToken, "evt-1", newDev.identity())
	if err != nil {
		t.Fatalf("same-event replay should return existing flow: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("expected same change id on replay, got %q vs %q", replay.ID, first.ID)
	}

	// 同事件不同内容（换了目标设备）：冲突。
	if _, err := svc.InitiateDeviceChange(pair.AccessToken, "evt-1", otherDev.identity()); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("expected ErrChangeConflict, got %v", err)
	}

	// 同一家族同时只允许一个活动流程。
	if _, err := svc.InitiateDeviceChange(pair.AccessToken, "evt-2", otherDev.identity()); !errors.Is(err, ErrChangeInProgress) {
		t.Fatalf("expected ErrChangeInProgress, got %v", err)
	}

	// 完成后同事件同内容仍返回已有状态，不同内容仍是冲突。
	completeRes := completeChangeWith(t, svc, first, oldDev, newDev)
	// 完成后旧访问令牌已失效（绑定版本变更）。
	if _, err := svc.InitiateDeviceChange(pair.AccessToken, "evt-1", newDev.identity()); !errors.Is(err, ErrDeviceBindingChanged) {
		t.Fatalf("initiating with an old-version access token must fail after rebind, got %v", err)
	}
	// 使用新设备的新访问令牌，同事件不同内容依然冲突。
	newAT := completeRes.TokenPair.AccessToken
	if _, err := svc.InitiateDeviceChange(newAT, "evt-1", otherDev.identity()); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("expected ErrChangeConflict after completion with other content, got %v", err)
	}
	// 同事件同内容用新令牌查询仍返回已完成状态。
	again, err := svc.InitiateDeviceChange(newAT, "evt-1", newDev.identity())
	if err != nil {
		t.Fatalf("completed event same-content replay should return status: %v", err)
	}
	if again.ID != first.ID || again.Status != StatusCompleted {
		t.Fatalf("expected completed existing flow, got %+v", again)
	}
}

func TestDeviceChangeExpiryThenRestartKeepsOldConfirmIsolated(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	old := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)
	oldSig := oldDev.signOldConfirm(old.Challenge, old.NewDeviceID, PublicKeyDigest(newDev.pub))

	// 流程过期：迟到的旧确认被拒绝且不改变任何状态。
	clock.Advance(11 * time.Minute)
	if _, err := svc.ConfirmDeviceChange(old.ID, oldSig); !errors.Is(err, ErrChangeExpired) {
		t.Fatalf("expected ErrChangeExpired, got %v", err)
	}
	stale, err := svc.GetDeviceChange(old.ID)
	if err != nil {
		t.Fatalf("GetDeviceChange: %v", err)
	}
	if stale.Status != StatusExpired || stale.OldConfirmed {
		t.Fatalf("expired flow must record no confirmations: %+v", stale)
	}

	// 过期后可以重新发起：先用未消耗的刷新令牌轮换出新的有效访问令牌
	//（访问令牌 TTL 1 分钟已过，刷新令牌 1 小时内仍有效）。
	freshPair := mustRefresh(t, svc, oldDev, pair.RefreshToken, clock, "")
	fresh := initiateChange(t, svc, freshPair.AccessToken, "evt-1", newDev)
	if fresh.ID == old.ID || fresh.Challenge == old.Challenge {
		t.Fatal("restarted change must have a new id and challenge")
	}

	// 旧流程的迟到确认不可能影响新流程。
	if _, err := svc.ConfirmDeviceChange(old.ID, oldSig); !errors.Is(err, ErrChangeExpired) {
		t.Fatalf("stale flow must stay expired, got %v", err)
	}
	active, err := svc.GetActiveDeviceChange(pair.FamilyID)
	if err != nil {
		t.Fatalf("GetActiveDeviceChange: %v", err)
	}
	if active.ID != fresh.ID || active.OldConfirmed {
		t.Fatalf("new flow must be unaffected by stale confirmation: %+v", active)
	}

	// 新流程正常完成。
	completeChangeWith(t, svc, fresh, oldDev, newDev)
}

func TestRevocationWinsOverDeviceChange(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)

	// 只完成旧确认，随后撤销家族。
	if _, err := svc.ConfirmDeviceChange(st.ID, oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub))); err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	if err := svc.RevokeFamily(pair.FamilyID); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	// 新设备证明迟到：撤销优先，流程不得继续完成。
	res, err := svc.ProvideNewDeviceProof(st.ID, newDev.signNewProof(st.Challenge, st.OldDeviceID))
	if !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
	if res != nil {
		t.Fatal("revoked family must not complete a device change")
	}
	// 双方都没有获得刷新资格：新旧设备刷新均被撤销拦截。
	if _, err := svc.Refresh(oldDev.signRefresh(pair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("old device refresh must observe revocation, got %v", err)
	}

	// 撤销后不能再发起新流程。
	if _, err := svc.InitiateDeviceChange(pair.AccessToken, "evt-2", newDev.identity()); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked when initiating on revoked family, got %v", err)
	}
}

func TestConcurrentRevokeAndChangeCompletion(t *testing.T) {
	// 无论确认与撤销如何竞争，都不允许出现"两个设备同时可刷新"。
	for i := 0; i < 50; i++ {
		clock := newFakeClock()
		svc := newTestService(t, NewMemoryStore(), clock)
		oldDev := newTestDevice(t, "device-old")
		newDev := newTestDevice(t, "device-new")

		pair, err := svc.Login("user-1", oldDev.identity())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)
		oldSig := oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub))
		newSig := newDev.signNewProof(st.Challenge, st.OldDeviceID)

		var wg sync.WaitGroup
		var stepRes *DeviceChangeStepResult
		var stepErr error
		wg.Add(3)
		go func() { defer wg.Done(); _, _ = svc.ConfirmDeviceChange(st.ID, oldSig) }()
		go func() {
			defer wg.Done()
			stepRes, stepErr = svc.ProvideNewDeviceProof(st.ID, newSig)
		}()
		go func() { defer wg.Done(); _ = svc.RevokeFamily(pair.FamilyID) }()
		wg.Wait()

		info, err := svc.GetFamilyBinding(pair.FamilyID)
		if err != nil {
			t.Fatalf("GetFamilyBinding: %v", err)
		}
		if !info.Revoked {
			t.Fatalf("iter %d: family must be revoked after racing revoke", i)
		}
		if stepErr == nil && stepRes.TokenPair != nil {
			// 换绑若先于撤销提交：交付的新令牌必须随家族立即失效。
			if _, err := svc.Refresh(newDev.signRefresh(stepRes.TokenPair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
				t.Fatalf("iter %d: new device token must be revoked, got %v", i, err)
			}
		}
		// 旧设备同样不可刷新。
		if _, err := svc.Refresh(oldDev.signRefresh(pair.RefreshToken, clock.Now(), "")); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("iter %d: old device must not retain refresh after revoke, got %v", i, err)
		}
	}
}

func TestOldDeviceLateIdempotentRefreshCannotFetchNewResult(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// 旧设备曾用幂等键 idem-9 成功轮换，结果缓存在 v1 键空间。
	cached := mustRefresh(t, svc, oldDev, pair.RefreshToken, clock, "idem-9")

	// 设备更换完成。
	st := initiateChange(t, svc, cached.AccessToken, "evt-1", newDev)
	res := completeChangeWith(t, svc, st, oldDev, newDev)
	delivered := res.TokenPair

	// 幂等窗口内，旧设备携带同一幂等键迟到重试：
	// 必须被设备绑定拦截，且绝不返回新设备的结果。
	retry, err := svc.Refresh(oldDev.signRefresh(pair.RefreshToken, clock.Now(), "idem-9"))
	if !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch for late old-device retry, got %v", err)
	}
	if retry != nil {
		t.Fatal("late old-device retry must not return any pair")
	}

	// 新设备使用同一个幂等键字符串也不受旧缓存影响（键空间隔离）。
	// 用新设备自己的刷新令牌 + 同名键完成一次刷新，得到的是新结果。
	next := mustRefresh(t, svc, newDev, delivered.RefreshToken, clock, "idem-9")
	if next.RefreshToken == cached.RefreshToken || next.AccessToken == cached.AccessToken {
		t.Fatal("new device must never receive the old device's cached result")
	}
	if next.BindingVersion != 2 {
		t.Fatalf("expected new device result at v2, got %d", next.BindingVersion)
	}
}

func TestDeviceChangeQueriesAndSecurityEvents(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	mustRefresh(t, svc, oldDev, pair.RefreshToken, clock, "")

	if _, err := svc.GetDeviceChange("devchg_missing"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("expected ErrChangeNotFound, got %v", err)
	}
	if _, err := svc.GetFamilyBinding("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound, got %v", err)
	}
	if _, err := svc.ListSecurityEvents("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound for events, got %v", err)
	}

	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)
	byEvent, err := svc.GetDeviceChangeByEvent(pair.FamilyID, "evt-1")
	if err != nil {
		t.Fatalf("GetDeviceChangeByEvent: %v", err)
	}
	if byEvent.ID != st.ID {
		t.Fatalf("event lookup mismatch: %q vs %q", byEvent.ID, st.ID)
	}

	completeChangeWith(t, svc, st, oldDev, newDev)

	// 活动流程查询：完成后应找不到。
	if _, err := svc.GetActiveDeviceChange(pair.FamilyID); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("expected no active change after completion, got %v", err)
	}

	events, err := svc.ListSecurityEvents(pair.FamilyID)
	if err != nil {
		t.Fatalf("ListSecurityEvents: %v", err)
	}
	var types []string
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	want := []string{
		EventLogin, EventRefresh,
		EventChangeInitiated, EventChangeOldConfirmed, EventChangeNewProved, EventChangeCompleted,
	}
	for _, w := range want {
		found := false
		for _, got := range types {
			if got == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing security event %q in %v", w, types)
		}
	}
	// 完成事件应记录新绑定版本与新世代。
	var completed *SecurityEventView
	for i := range events {
		if events[i].Type == EventChangeCompleted {
			completed = &events[i]
		}
	}
	if completed == nil || completed.BindingVersion != 2 || completed.Detail["new_device_id"] != "device-new" {
		t.Fatalf("unexpected completed event: %+v", completed)
	}
}

func TestPersistedChangeStateContainsNoSecrets(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	clock := newFakeClock()
	svc := newTestService(t, store, clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")

	pair, err := svc.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := initiateChange(t, svc, pair.AccessToken, "evt-1", newDev)
	completeChangeWith(t, svc, st, oldDev, newDev)

	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	content := string(data)
	// 令牌明文、双方裸公钥、签名都不得落盘。
	if strings.Contains(content, pair.RefreshToken) || strings.Contains(content, pair.AccessToken) {
		t.Fatal("state file must not contain token plaintext")
	}
	if strings.Contains(content, hexEncode(oldDev.pub)) || strings.Contains(content, hexEncode(newDev.pub)) {
		t.Fatal("state file must not contain raw public keys")
	}
	if strings.Contains(content, base64RawURL(oldDev.pub)) || strings.Contains(content, base64RawURL(newDev.pub)) {
		t.Fatal("state file must not contain raw public keys (base64)")
	}
	// 完成后挑战应已清除；待处理流程的挑战是一次性非秘密随机值，完成后不应残留。
	if strings.Contains(content, st.Challenge) {
		t.Fatal("completed change challenge must be purged from persisted state")
	}
	// 设备标识与公钥摘要可以保留。
	if !strings.Contains(content, "device-new") || !strings.Contains(content, PublicKeyDigest(newDev.pub)) {
		t.Fatal("state file should retain device id and public key digest")
	}
}

func TestDeviceChangeSurvivesRestart(t *testing.T) {
	clock := newFakeClock()
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")

	svc1 := newTestService(t, store, clock)
	oldDev := newTestDevice(t, "device-old")
	newDev := newTestDevice(t, "device-new")
	pair, err := svc1.Login("user-1", oldDev.identity())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := initiateChange(t, svc1, pair.AccessToken, "evt-1", newDev)
	// 仅完成旧确认后重启：进度必须保留。
	if _, err := svc1.ConfirmDeviceChange(st.ID, oldDev.signOldConfirm(st.Challenge, st.NewDeviceID, PublicKeyDigest(newDev.pub))); err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}

	svc2 := newTestService(t, store, clock)
	mid, err := svc2.GetDeviceChange(st.ID)
	if err != nil {
		t.Fatalf("GetDeviceChange after restart: %v", err)
	}
	if !mid.OldConfirmed || mid.NewProved {
		t.Fatalf("change progress must survive restart: %+v", mid)
	}
	// 已记录的安全事件也必须随状态恢复。
	events, err := svc2.ListSecurityEvents(pair.FamilyID)
	if err != nil {
		t.Fatalf("ListSecurityEvents after restart: %v", err)
	}
	var seenConfirm bool
	for _, ev := range events {
		if ev.Type == EventChangeOldConfirmed {
			seenConfirm = true
		}
	}
	if !seenConfirm {
		t.Fatalf("old-confirm security event must survive restart, got %+v", events)
	}
	res, err := svc2.ProvideNewDeviceProof(st.ID, newDev.signNewProof(mid.Challenge, mid.OldDeviceID))
	if err != nil {
		t.Fatalf("ProvideNewDeviceProof after restart: %v", err)
	}
	if res.TokenPair == nil || res.TokenPair.BindingVersion != 2 {
		t.Fatalf("expected completion pair at v2 after restart, got %+v", res.TokenPair)
	}
	info, err := svc2.GetFamilyBinding(pair.FamilyID)
	if err != nil {
		t.Fatalf("GetFamilyBinding after restart: %v", err)
	}
	if info.DeviceID != "device-new" || info.BindingVersion != 2 {
		t.Fatalf("rebinding must survive restart: %+v", info)
	}
}
