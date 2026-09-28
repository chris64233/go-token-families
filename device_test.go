package tokenfamilies

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// confirmReq 构造旧设备确认更换的请求。
func (d *testDevice) confirmReq(familyID, changeID, nonce, newDeviceID string, newPub ed25519.PublicKey) ConfirmChangeRequest {
	msg := DeviceChangeConfirmMessage(familyID, changeID, nonce, newDeviceID, keyDigest(newPub))
	return ConfirmChangeRequest{
		FamilyID:        familyID,
		ChangeID:        changeID,
		DeviceID:        d.id,
		DevicePublicKey: d.pub,
		Signature:       ed25519.Sign(d.priv, msg),
	}
}

// proveReq 构造新设备证明持有私钥的请求。
func (d *testDevice) proveReq(familyID, changeID, nonce string) ProveChangeRequest {
	msg := DeviceChangeProveMessage(familyID, changeID, nonce)
	return ProveChangeRequest{
		FamilyID:        familyID,
		ChangeID:        changeID,
		DeviceID:        d.id,
		DevicePublicKey: d.pub,
		Signature:       ed25519.Sign(d.priv, msg),
	}
}

func initChange(t *testing.T, svc *Service, familyID, changeID string, newDev *testDevice) *DeviceChangeStatus {
	t.Helper()
	st, err := svc.InitiateDeviceChange(DeviceChangeRequest{
		FamilyID:           familyID,
		ChangeID:           changeID,
		NewDeviceID:        newDev.id,
		NewDevicePublicKey: newDev.pub,
	})
	if err != nil {
		t.Fatalf("InitiateDeviceChange: %v", err)
	}
	if st.Phase != PhasePendingOldConfirm || st.Nonce == "" {
		t.Fatalf("unexpected initial status: %+v", st)
	}
	return st
}

// completeDeviceChange 走完整更换流程并在提交后做基本断言。
func completeDeviceChange(t *testing.T, svc *Service, pair *TokenPair, oldDev, newDev *testDevice) *TokenPair {
	t.Helper()
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	out, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	if out.Tokens != nil || out.Status.Phase != PhasePendingNewProof {
		t.Fatalf("after old confirm only, change must not commit: %+v", out.Status)
	}

	// 仅完成旧设备确认时，家族仍绑定旧设备，旧设备仍具备刷新资格。
	if info, err := svc.FamilyBinding(pair.FamilyID); err != nil || info.BindingVersion != 1 || info.DeviceID != oldDev.id {
		t.Fatalf("family must stay bound to old device mid-flow: %+v err=%v", info, err)
	}

	out, err = svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
	if err != nil {
		t.Fatalf("ProveDeviceChange: %v", err)
	}
	if out.Tokens == nil {
		t.Fatal("completing both steps must atomically return a rotated token pair")
	}
	if out.Status.Phase != PhaseCommitted || out.Status.CommittedAt == nil {
		t.Fatalf("expected committed status, got %+v", out.Status)
	}
	return out.Tokens
}

func TestRefreshRequiresDeviceBindingAndSignature(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")
	other := newTestDevice(t, "dev-2")
	pair := login(t, svc, "user-1", dev)

	// 设备标识不匹配。
	req := dev.refreshReq(pair.RefreshToken, "")
	req.DeviceID = other.id
	if _, err := svc.Refresh(req); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch for device id, got %v", err)
	}
	// 公钥不属于绑定设备。
	req = dev.refreshReq(pair.RefreshToken, "")
	req.DeviceID = dev.id
	req.DevicePublicKey = other.pub
	if _, err := svc.Refresh(req); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch for foreign key, got %v", err)
	}
	// 签名无效。
	req = dev.refreshReq(pair.RefreshToken, "")
	req.Signature = []byte("not-a-signature")
	if _, err := svc.Refresh(req); !errors.Is(err, ErrInvalidDeviceProof) {
		t.Fatalf("expected ErrInvalidDeviceProof, got %v", err)
	}
	// 用另一台设备的私钥签名。
	req = RefreshRequest{
		RefreshToken:    pair.RefreshToken,
		DeviceID:        dev.id,
		DevicePublicKey: dev.pub,
		Signature:       ed25519.Sign(other.priv, RefreshMessage(pair.RefreshToken, "")),
	}
	if _, err := svc.Refresh(req); !errors.Is(err, ErrInvalidDeviceProof) {
		t.Fatalf("expected ErrInvalidDeviceProof for foreign signature, got %v", err)
	}

	// 未通过设备证明的旧令牌重用不得触发家族撤销。
	rotated, err := svc.Refresh(dev.refreshReq(pair.RefreshToken, ""))
	if err != nil {
		t.Fatalf("valid rotation: %v", err)
	}
	if _, err := svc.Refresh(req); !errors.Is(err, ErrInvalidDeviceProof) {
		t.Fatalf("bad proof on consumed token must stay ErrInvalidDeviceProof, got %v", err)
	}
	// 家族仍然有效，当前刷新令牌可继续轮换。
	if _, err := svc.Refresh(dev.refreshReq(rotated.RefreshToken, "")); err != nil {
		t.Fatalf("family must not be revoked by an unauthenticated replay attempt: %v", err)
	}
}

func TestLoginRejectsEmptyDeviceBinding(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	dev := newTestDevice(t, "dev-1")
	if _, err := svc.Login("user-1", "", dev.pub); err == nil {
		t.Fatal("Login without device id must fail")
	}
	if _, err := svc.Login("user-1", "dev-1", nil); err == nil {
		t.Fatal("Login without device public key must fail")
	}
}

func TestDeviceChangeFullFlowSwitchesBindingAtomically(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")

	pair := login(t, svc, "user-1", oldDev)
	newPair := completeDeviceChange(t, svc, pair, oldDev, newDev)

	// 绑定已切换且版本递增。
	info, err := svc.FamilyBinding(pair.FamilyID)
	if err != nil {
		t.Fatalf("FamilyBinding: %v", err)
	}
	if info.DeviceID != "dev-new" || info.BindingVersion != 2 || info.Revoked {
		t.Fatalf("unexpected binding after switch: %+v", info)
	}

	// 旧设备时代的访问令牌立即失效，新令牌有效并反映新绑定。
	if _, err := svc.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrDeviceBindingChanged) {
		t.Fatalf("expected ErrDeviceBindingChanged for old access token, got %v", err)
	}
	claims, err := svc.ValidateAccessToken(newPair.AccessToken)
	if err != nil {
		t.Fatalf("new access token must validate: %v", err)
	}
	if claims.DeviceID != "dev-new" || claims.BindingVersion != 2 {
		t.Fatalf("claims must reflect new binding: %+v", claims)
	}

	// 旧设备的旧刷新令牌不能刷新（设备校验先于重放，也不会触发撤销）。
	if _, err := svc.Refresh(oldDev.refreshReq(pair.RefreshToken, "")); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("old device must lose refresh eligibility, got %v", err)
	}
	// 新设备持轮换结果刷新成功。
	next, err := svc.Refresh(newDev.refreshReq(newPair.RefreshToken, ""))
	if err != nil {
		t.Fatalf("new device must be able to refresh: %v", err)
	}
	// 世代单调延续：登录第 1 代，提交时签发第 2 代，此处为第 3 代。
	if rec := svc.state.RefreshTokens[digest(next.RefreshToken)]; rec.Generation != 3 {
		t.Fatalf("expected generation 3 after switch rotation, got %d", rec.Generation)
	}
	// 家族未被撤销：任何时刻都不允许两个设备同时具备资格，
	// 切换属正常流程，不是攻击。
	if info, _ := svc.FamilyBinding(pair.FamilyID); info.Revoked {
		t.Fatal("device switch must not revoke the family")
	}
}

func TestDeviceChangeNewProofFirstThenOldConfirmCommits(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	out, err := svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
	if err != nil {
		t.Fatalf("ProveDeviceChange: %v", err)
	}
	if out.Tokens != nil || out.Status.Phase != PhasePendingOldConfirm {
		t.Fatalf("new proof alone must not commit: %+v", out.Status)
	}
	out, err = svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	if out.Tokens == nil || out.Status.Phase != PhaseCommitted {
		t.Fatalf("expected atomic commit on second step, got %+v", out.Status)
	}
}

func TestDeviceChangeStepIdempotencyAndReplayAfterCommit(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	first, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	// 相同内容重放确认：返回已有状态，不报错、不推进。
	replay, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil || replay.Status.Phase != first.Status.Phase || replay.Tokens != nil {
		t.Fatalf("idempotent confirm replay must return existing state: %+v err=%v", replay, err)
	}

	committed, err := svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
	if err != nil || committed.Tokens == nil {
		t.Fatalf("ProveDeviceChange commit: %v", err)
	}
	// 提交后的迟到确认/证明返回已提交状态，不重新轮换、不报错。
	late, err := svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
	if err != nil || late.Status.Phase != PhaseCommitted || late.Tokens != nil {
		t.Fatalf("late proof after commit must report committed without tokens: %+v err=%v", late, err)
	}
	late2, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil || late2.Status.Phase != PhaseCommitted || late2.Tokens != nil {
		t.Fatalf("late confirm after commit must report committed without tokens: %+v err=%v", late2, err)
	}
}

func TestDeviceChangeWrongDeviceOrBadProofDoesNotAdvance(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	intruder := newTestDevice(t, "dev-x")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	// 旧设备确认不能由其他设备完成。
	bad := oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)
	bad.DeviceID = intruder.id
	bad.DevicePublicKey = intruder.pub
	bad.Signature = ed25519.Sign(intruder.priv,
		DeviceChangeConfirmMessage(pair.FamilyID, "chg-1", st.Nonce, newDev.id, keyDigest(newDev.pub)))
	if _, err := svc.ConfirmDeviceChange(bad); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch, got %v", err)
	}
	// 签名错误。
	bad = oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)
	bad.Signature = []byte("bad")
	if _, err := svc.ConfirmDeviceChange(bad); !errors.Is(err, ErrInvalidDeviceProof) {
		t.Fatalf("expected ErrInvalidDeviceProof, got %v", err)
	}
	// 新设备证明必须来自登记的新设备。
	badP := newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce)
	badP.DeviceID = intruder.id
	badP.DevicePublicKey = intruder.pub
	badP.Signature = ed25519.Sign(intruder.priv, DeviceChangeProveMessage(pair.FamilyID, "chg-1", st.Nonce))
	if _, err := svc.ProveDeviceChange(badP); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("expected ErrDeviceMismatch for proof from other device, got %v", err)
	}

	// 流程未推进，合法的确认与证明仍能完成更换。
	out, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil || out.Status.Phase != PhasePendingNewProof {
		t.Fatalf("valid confirm should advance after rejected attempts: %+v err=%v", out, err)
	}
}

func TestDeviceChangeInitiateIdempotencyAndConflict(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	other := newTestDevice(t, "dev-other")
	pair := login(t, svc, "user-1", oldDev)

	st1 := initChange(t, svc, pair.FamilyID, "chg-1", newDev)
	// 相同更换事件相同内容重放：返回已有状态（Nonce 不变）。
	st2, err := svc.InitiateDeviceChange(DeviceChangeRequest{
		FamilyID: pair.FamilyID, ChangeID: "chg-1",
		NewDeviceID: newDev.id, NewDevicePublicKey: newDev.pub,
	})
	if err != nil || st2.Nonce != st1.Nonce || st2.Phase != PhasePendingOldConfirm {
		t.Fatalf("replay initiate must return existing state: %+v err=%v", st2, err)
	}
	// 同号异内容冲突：新设备 ID 不同。
	if _, err := svc.InitiateDeviceChange(DeviceChangeRequest{
		FamilyID: pair.FamilyID, ChangeID: "chg-1",
		NewDeviceID: other.id, NewDevicePublicKey: other.pub,
	}); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("expected ErrChangeConflict for different content, got %v", err)
	}
	// 同号异内容冲突：设备 ID 相同但公钥不同。
	if _, err := svc.InitiateDeviceChange(DeviceChangeRequest{
		FamilyID: pair.FamilyID, ChangeID: "chg-1",
		NewDeviceID: newDev.id, NewDevicePublicKey: other.pub,
	}); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("expected ErrChangeConflict for different key, got %v", err)
	}
}

func TestDeviceChangeExpiredCanReinitiateAndOldConfirmIgnored(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, NewMemoryStore(), clock)
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)

	st1 := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	// 过期后确认/证明被拒绝，进度查询反映 expired。
	clock.Advance(6 * time.Minute)
	if qs, err := svc.DeviceChangeStatus(pair.FamilyID, "chg-1"); err != nil || qs.Phase != PhaseExpired {
		t.Fatalf("expected expired phase, got %+v err=%v", qs, err)
	}
	if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st1.Nonce, newDev.id, newDev.pub)); !errors.Is(err, ErrChangeExpired) {
		t.Fatalf("expected ErrChangeExpired, got %v", err)
	}

	// 相同事件 + 相同内容重新发起：生成新 Nonce。
	st2, err := svc.InitiateDeviceChange(DeviceChangeRequest{
		FamilyID: pair.FamilyID, ChangeID: "chg-1",
		NewDeviceID: newDev.id, NewDevicePublicKey: newDev.pub,
	})
	if err != nil {
		t.Fatalf("re-initiate after expiry: %v", err)
	}
	if st2.Nonce == st1.Nonce {
		t.Fatal("re-initiated flow must use a fresh nonce")
	}

	// 旧流程的迟到确认（签在旧 Nonce 上）必须失败，不得影响新流程。
	if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st1.Nonce, newDev.id, newDev.pub)); !errors.Is(err, ErrInvalidDeviceProof) {
		t.Fatalf("late confirm of stale flow must be rejected, got %v", err)
	}
	if qs, _ := svc.DeviceChangeStatus(pair.FamilyID, "chg-1"); qs.OldConfirmed {
		t.Fatal("stale confirm must not advance the new flow")
	}

	// 新流程可以正常完成。
	out, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st2.Nonce, newDev.id, newDev.pub))
	if err != nil || out.Status.Phase != PhasePendingNewProof {
		t.Fatalf("fresh confirm: %+v err=%v", out, err)
	}
	out, err = svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st2.Nonce))
	if err != nil || out.Tokens == nil {
		t.Fatalf("fresh proof must commit: %+v err=%v", out, err)
	}
}

func TestNewerChangeSupersedesPendingOne(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	devA := newTestDevice(t, "dev-a")
	devB := newTestDevice(t, "dev-b")
	pair := login(t, svc, "user-1", oldDev)

	stA := initChange(t, svc, pair.FamilyID, "chg-a", devA)
	_ = initChange(t, svc, pair.FamilyID, "chg-b", devB)

	// 旧流程已被取代：其确认找不到流程，无法影响家族绑定。
	if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-a", stA.Nonce, devA.id, devA.pub)); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("superseded change must be gone, got %v", err)
	}
	// 家族仍绑定旧设备。
	if info, _ := svc.FamilyBinding(pair.FamilyID); info.DeviceID != oldDev.id || info.BindingVersion != 1 {
		t.Fatalf("superseded flow must not change binding: %+v", info)
	}
}

func TestRevokeWinsOverDeviceChange(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)

	// 撤销后不能发起更换。
	if err := svc.RevokeFamily(pair.FamilyID); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if _, err := svc.InitiateDeviceChange(DeviceChangeRequest{
		FamilyID: pair.FamilyID, ChangeID: "chg-x",
		NewDeviceID: newDev.id, NewDevicePublicKey: newDev.pub,
	}); !errors.Is(err, ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked on initiate, got %v", err)
	}
}

func TestRevokeWinsOverPendingDeviceChangeSteps(t *testing.T) {
	// 进行中的更换被撤销：确认与证明都必须失败，家族保持撤销。
	for _, revokeAt := range []int{0, 1} {
		svc := newTestService(t, NewMemoryStore(), newFakeClock())
		oldDev := newTestDevice(t, "dev-old")
		newDev := newTestDevice(t, "dev-new")
		pair := login(t, svc, "user-1", oldDev)
		st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

		if revokeAt == 1 {
			if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)); err != nil {
				t.Fatalf("ConfirmDeviceChange: %v", err)
			}
		}
		if err := svc.RevokeFamily(pair.FamilyID); err != nil {
			t.Fatalf("RevokeFamily: %v", err)
		}
		if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("revokeAt=%d: confirm must observe revocation: %v", revokeAt, err)
		}
		if _, err := svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce)); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("revokeAt=%d: proof must observe revocation: %v", revokeAt, err)
		}
		if info, _ := svc.FamilyBinding(pair.FamilyID); !info.Revoked || info.DeviceID != oldDev.id {
			t.Fatalf("revokeAt=%d: family must stay revoked and bound to old device: %+v", revokeAt, info)
		}
	}
}

func TestConcurrentCommitAndRevoke(t *testing.T) {
	// 无论提交与撤销谁先进入临界区，最终状态必须自洽：
	// 要么家族撤销（提交可能先发生，但其新令牌同样被撤销），
	// 要么更换提交成功且家族未撤销。
	for i := 0; i < 50; i++ {
		svc := newTestService(t, NewMemoryStore(), newFakeClock())
		oldDev := newTestDevice(t, "dev-old")
		newDev := newTestDevice(t, "dev-new")
		pair := login(t, svc, "user-1", oldDev)
		st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)
		if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)); err != nil {
			t.Fatalf("iter %d ConfirmDeviceChange: %v", i, err)
		}

		var wg sync.WaitGroup
		var out *DeviceChangeOutcome
		var proveErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			out, proveErr = svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
		}()
		go func() {
			defer wg.Done()
			_ = svc.RevokeFamily(pair.FamilyID)
		}()
		wg.Wait()

		info, _ := svc.FamilyBinding(pair.FamilyID)
		switch {
		case info.Revoked:
			// 撤销最终生效；若提交先发生，其令牌对也必须随家族不可用。
			if proveErr == nil && out.Tokens != nil {
				if _, err := svc.Refresh(newDev.refreshReq(out.Tokens.RefreshToken, "")); !errors.Is(err, ErrFamilyRevoked) {
					t.Fatalf("iter %d: committed tokens must be revoked, got %v", i, err)
				}
			}
		default:
			// 提交最终生效：家族绑定新设备且新令牌可用，撤销必然未发生。
			if proveErr != nil || out.Tokens == nil {
				t.Fatalf("iter %d: non-revoked family but commit failed: %v", i, proveErr)
			}
			if info.DeviceID != newDev.id {
				t.Fatalf("iter %d: unexpected binding: %+v", i, info)
			}
			if _, err := svc.Refresh(newDev.refreshReq(out.Tokens.RefreshToken, "")); err != nil {
				t.Fatalf("iter %d: new device tokens must work: %v", i, err)
			}
			if _, err := svc.Refresh(oldDev.refreshReq(pair.RefreshToken, "")); !errors.Is(err, ErrDeviceMismatch) {
				t.Fatalf("iter %d: old device must never retain eligibility, got %v", i, err)
			}
		}
	}
}

func TestLateIdempotentRefreshFromOldDeviceAfterSwitchRejected(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")

	pair := login(t, svc, "user-1", oldDev)
	// 旧设备的一次轮换在幂等窗口内缓存了结果。
	rotated, err := svc.Refresh(oldDev.refreshReq(pair.RefreshToken, "idem-old"))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// 完成设备切换（提交会使 rotated 的刷新令牌也失效）。
	newPair := completeDeviceChange(t, svc, rotated, oldDev, newDev)
	_ = newPair

	// 旧设备对切换前请求的迟到重试：幂等键仍在窗口内，但不得取回任何令牌结果。
	if _, err := svc.Refresh(oldDev.refreshReq(pair.RefreshToken, "idem-old")); !errors.Is(err, ErrDeviceBindingChanged) {
		t.Fatalf("late idempotent retry must be rejected with ErrDeviceBindingChanged, got %v", err)
	}
}

func TestConcurrentConfirmAndProveCommitOnce(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	var wg sync.WaitGroup
	var oldOut, newOut *DeviceChangeOutcome
	var oldErr, newErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		oldOut, oldErr = svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	}()
	go func() {
		defer wg.Done()
		newOut, newErr = svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
	}()
	wg.Wait()
	if oldErr != nil || newErr != nil {
		t.Fatalf("steps: old=%v new=%v", oldErr, newErr)
	}
	committed := 0
	if oldOut.Tokens != nil {
		committed++
	}
	if newOut.Tokens != nil {
		committed++
	}
	if committed != 1 {
		t.Fatalf("exactly one step must return the rotated pair, got %d", committed)
	}
	// 两步都返回后流程必然已提交（先完成的一步其响应快照可能仍是等待态）。
	qs, err := svc.DeviceChangeStatus(pair.FamilyID, "chg-1")
	if err != nil || qs.Phase != PhaseCommitted {
		t.Fatalf("final status must be committed: %+v err=%v", qs, err)
	}
}

func TestDeviceChangeStatusAndEventsQueries(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)
	if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)); err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}

	// 进度查询。
	qs, err := svc.DeviceChangeStatus(pair.FamilyID, "chg-1")
	if err != nil {
		t.Fatalf("DeviceChangeStatus: %v", err)
	}
	if qs.Phase != PhasePendingNewProof || !qs.OldConfirmed || qs.NewProved {
		t.Fatalf("unexpected progress: %+v", qs)
	}
	if _, err := svc.DeviceChangeStatus(pair.FamilyID, "missing"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("expected ErrChangeNotFound, got %v", err)
	}
	if _, err := svc.DeviceChangeStatus("fam_missing", "chg-1"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("expected ErrChangeNotFound for other family, got %v", err)
	}

	// 绑定查询。
	info, err := svc.FamilyBinding(pair.FamilyID)
	if err != nil {
		t.Fatalf("FamilyBinding: %v", err)
	}
	if info.BindingVersion != 1 || info.DeviceID != "dev-old" || len(info.KeyDigestPrefix) != 8 {
		t.Fatalf("unexpected binding info: %+v", info)
	}
	if info.KeyDigestPrefix != keyDigest(oldDev.pub)[:8] {
		t.Fatal("key digest prefix mismatch")
	}

	// 完成提交后查询事件。
	if _, err := svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce)); err != nil {
		t.Fatalf("ProveDeviceChange: %v", err)
	}
	events, err := svc.SecurityEvents(pair.FamilyID)
	if err != nil {
		t.Fatalf("SecurityEvents: %v", err)
	}
	var types []string
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	want := []string{
		EventLogin, EventDeviceChangeInitiated, EventDeviceChangeOldConfirmed,
		EventDeviceChangeNewProved, EventDeviceChangeCommitted,
	}
	if fmt.Sprint(types) != fmt.Sprint(want) {
		t.Fatalf("unexpected event sequence: %v", types)
	}
	for _, ev := range events {
		if ev.FamilyID != pair.FamilyID || ev.At.IsZero() {
			t.Fatalf("event missing metadata: %+v", ev)
		}
	}
	if _, err := svc.SecurityEvents("fam_missing"); !errors.Is(err, ErrFamilyNotFound) {
		t.Fatalf("expected ErrFamilyNotFound, got %v", err)
	}
}

func TestDeviceChangePersistsAcrossRestart(t *testing.T) {
	clock := newFakeClock()
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")

	svc1 := newTestService(t, store, clock)
	pair := login(t, svc1, "user-1", oldDev)
	st := initChange(t, svc1, pair.FamilyID, "chg-1", newDev)

	// 重启后完成旧设备确认。
	svc2 := newTestService(t, store, clock)
	out, err := svc2.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub))
	if err != nil {
		t.Fatalf("confirm after restart: %v", err)
	}
	if out.Status.Phase != PhasePendingNewProof {
		t.Fatalf("unexpected phase after restart: %+v", out.Status)
	}

	// 再次重启后完成新设备证明并提交。
	svc3 := newTestService(t, store, clock)
	out, err = svc3.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce))
	if err != nil {
		t.Fatalf("prove after restart: %v", err)
	}
	if out.Tokens == nil {
		t.Fatal("commit after restart must return rotated tokens")
	}
	if _, err := svc3.Refresh(newDev.refreshReq(out.Tokens.RefreshToken, "")); err != nil {
		t.Fatalf("new device refresh after restart: %v", err)
	}
	if _, err := svc3.Refresh(oldDev.refreshReq(pair.RefreshToken, "")); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("old device must be rejected after restart, got %v", err)
	}
}

func TestPersistedStateContainsNoKeysOrProofs(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir + "/state.json")
	svc := newTestService(t, store, newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)
	if _, err := svc.ConfirmDeviceChange(oldDev.confirmReq(pair.FamilyID, "chg-1", st.Nonce, newDev.id, newDev.pub)); err != nil {
		t.Fatalf("ConfirmDeviceChange: %v", err)
	}
	if _, err := svc.ProveDeviceChange(newDev.proveReq(pair.FamilyID, "chg-1", st.Nonce)); err != nil {
		t.Fatalf("ProveDeviceChange: %v", err)
	}

	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	content := string(data)
	for _, dev := range []*testDevice{oldDev, newDev} {
		raw := string(dev.pub)
		if strings.Contains(content, raw) {
			t.Fatal("persisted state must not contain raw device public keys")
		}
		b64 := base64.StdEncoding.EncodeToString(dev.pub)
		if strings.Contains(content, b64) {
			t.Fatal("persisted state must not contain base64 public keys")
		}
		hx := hex.EncodeToString(dev.pub)
		if strings.Contains(content, hx) {
			t.Fatal("persisted state must not contain hex public keys")
		}
	}
	if strings.Contains(content, pair.RefreshToken) || strings.Contains(content, pair.AccessToken) {
		t.Fatal("persisted state must not contain plaintext tokens")
	}
}

func TestStatusViewsContainNoSensitiveValues(t *testing.T) {
	svc := newTestService(t, NewMemoryStore(), newFakeClock())
	oldDev := newTestDevice(t, "dev-old")
	newDev := newTestDevice(t, "dev-new")
	pair := login(t, svc, "user-1", oldDev)
	st := initChange(t, svc, pair.FamilyID, "chg-1", newDev)

	text := fmt.Sprintf("%+v", st)
	if strings.Contains(text, string(newDev.pub)) {
		t.Fatal("change status must not expose the public key")
	}
	if strings.Contains(text, pair.RefreshToken) {
		t.Fatal("change status must not expose tokens")
	}

	info, _ := svc.FamilyBinding(pair.FamilyID)
	if strings.Contains(fmt.Sprintf("%+v", info), string(oldDev.pub)) {
		t.Fatal("binding info must not expose the full public key")
	}
}
