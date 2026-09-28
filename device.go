package tokenfamilies

import (
	"fmt"
	"time"
)

// 安全事件类型。SecurityEvents 返回的事件 Type 字段取值于此。
const (
	EventLogin                    = "login"
	EventRefresh                  = "refresh"
	EventReplayRevoke             = "replay_revoke"
	EventManualRevoke             = "manual_revoke"
	EventDeviceChangeInitiated    = "device_change_initiated"
	EventDeviceChangeOldConfirmed = "device_change_old_confirmed"
	EventDeviceChangeNewProved    = "device_change_new_proved"
	EventDeviceChangeCommitted    = "device_change_committed"
	EventDeviceChangeSuperseded   = "device_change_superseded"
)

// maxEventsPerFamily 是每个家族保留的安全事件条数上限。
const maxEventsPerFamily = 200

// ChangePhase 描述设备更换流程的进度。
type ChangePhase string

const (
	// PhasePendingOldConfirm 等待旧设备确认。
	PhasePendingOldConfirm ChangePhase = "pending_old_confirm"
	// PhasePendingNewProof 旧设备已确认，等待新设备证明持有私钥。
	PhasePendingNewProof ChangePhase = "pending_new_proof"
	// PhaseCommitted 更换已提交：家族已绑定新设备并完成令牌轮换。
	PhaseCommitted ChangePhase = "committed"
	// PhaseExpired 确认流程已过期，可重新发起。
	PhaseExpired ChangePhase = "expired"
)

// DeviceChangeRequest 是发起设备更换的请求。
// 调用方（应用层）必须先完成用户级身份认证；本服务假定发起者
// 已获用户授权，更换最终仍需旧设备确认 + 新设备证明才能生效。
type DeviceChangeRequest struct {
	FamilyID string
	// ChangeID 是更换事件标识，作为幂等键：
	// 相同 ChangeID + 相同内容的重复发起返回已有状态；
	// 相同 ChangeID + 不同内容返回 ErrChangeConflict。
	ChangeID    string
	NewDeviceID string
	// NewDevicePublicKey 是新设备公钥，仅用于计算不可逆摘要，绝不持久化。
	NewDevicePublicKey []byte
}

// DeviceChangeStatus 是设备更换流程的进度视图，不包含任何敏感值
// （公钥、签名、令牌），Nonce 只是防重放随机因子。
type DeviceChangeStatus struct {
	ChangeID    string
	FamilyID    string
	NewDeviceID string
	// Nonce 是本次尝试的防重放因子；确认与证明的签名消息必须包含它。
	Nonce        string
	Phase        ChangePhase
	OldConfirmed bool
	NewProved    bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
	CommittedAt  *time.Time
}

// DeviceChangeOutcome 是确认/证明一步的结果。
type DeviceChangeOutcome struct {
	Status DeviceChangeStatus
	// Tokens 仅当本调用触发了更换提交（旧设备确认与新设备证明均已完备）
	// 时返回：更换提交会立即轮换刷新令牌，新令牌对交给新设备。
	Tokens *TokenPair
}

// ConfirmChangeRequest 是旧设备确认更换的请求。
type ConfirmChangeRequest struct {
	FamilyID string
	ChangeID string
	// DeviceID 与 DevicePublicKey 必须匹配家族当前（旧）绑定。
	DeviceID        string
	DevicePublicKey []byte
	// Signature 是旧设备私钥对 DeviceChangeConfirmMessage 的签名。
	Signature []byte
}

// ProveChangeRequest 是新设备证明持有私钥的请求。
type ProveChangeRequest struct {
	FamilyID string
	ChangeID string
	// DeviceID 与 DevicePublicKey 必须匹配发起时登记的新设备。
	DeviceID        string
	DevicePublicKey []byte
	// Signature 是新设备私钥对 DeviceChangeProveMessage 的签名。
	Signature []byte
}

// BindingInfo 是家族当前设备绑定的查询视图，不包含任何敏感值。
type BindingInfo struct {
	FamilyID       string
	DeviceID       string
	BindingVersion int
	// KeyDigestPrefix 是设备公钥摘要的前 8 个十六进制字符，仅用于界面比对。
	KeyDigestPrefix string
	BoundAt         time.Time
	Revoked         bool
}

// InitiateDeviceChange 发起一次设备更换，生成短期有效的一次性确认流程。
//
//   - 相同 ChangeID + 相同内容的重复发起返回已有状态（幂等重放）；
//   - 相同 ChangeID + 不同内容返回 ErrChangeConflict；
//   - 流程过期后可用同一 ChangeID + 相同内容重新发起：会生成新的
//     防重放 Nonce 与新的过期时间，旧流程的迟到确认对新流程无效；
//   - 同一家族已有进行中的更换时，新发起会取代旧流程。
func (s *Service) InitiateDeviceChange(req DeviceChangeRequest) (*DeviceChangeStatus, error) {
	if req.FamilyID == "" || req.ChangeID == "" || req.NewDeviceID == "" || len(req.NewDevicePublicKey) == 0 {
		return nil, fmt.Errorf("tokenfamilies: family id, change id, new device id and public key must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	fam, ok := s.state.Families[req.FamilyID]
	if !ok {
		return nil, ErrFamilyNotFound
	}
	if fam.Revoked {
		return nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	newDigest := keyDigest(req.NewDevicePublicKey)

	if existing, ok := s.state.DeviceChanges[req.ChangeID]; ok {
		if existing.FamilyID != req.FamilyID ||
			existing.NewDeviceID != req.NewDeviceID ||
			existing.NewKeyDigest != newDigest {
			return nil, fmt.Errorf("tokenfamilies: change id reused with different content: %w", ErrChangeConflict)
		}
		if existing.Committed || now.Before(existing.ExpiresAt) {
			// 幂等重放：返回已有状态，不重复发起。
			return changeStatus(existing, now), nil
		}
		// 已过期：作为新一次尝试重新发起，更换 Nonce 使旧确认失效。
		if err := s.resetChangeLocked(existing, now); err != nil {
			return nil, err
		}
		s.recordEventLocked(fam, EventDeviceChangeInitiated, "change_id="+existing.ChangeID+" retry", now)
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		return changeStatus(existing, now), nil
	}

	// 取代同一家族其他尚未完成的更换流程：旧流程的迟到确认随即失效。
	for id, ch := range s.state.DeviceChanges {
		if ch.FamilyID == fam.ID && !ch.Committed && now.Before(ch.ExpiresAt) {
			delete(s.state.DeviceChanges, id)
			s.recordEventLocked(fam, EventDeviceChangeSuperseded, "change_id="+id, now)
		}
	}

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	ch := &DeviceChange{
		ChangeID:     req.ChangeID,
		FamilyID:     req.FamilyID,
		NewDeviceID:  req.NewDeviceID,
		NewKeyDigest: newDigest,
		Nonce:        nonce,
		CreatedAt:    now,
		ExpiresAt:    now.Add(s.cfg.DeviceChangeTTL),
	}
	s.state.DeviceChanges[ch.ChangeID] = ch
	s.recordEventLocked(fam, EventDeviceChangeInitiated, "change_id="+ch.ChangeID, now)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	s.cfg.Logger.Info("device change initiated", "family_id", fam.ID, "change_id", ch.ChangeID)
	return changeStatus(ch, now), nil
}

// ConfirmDeviceChange 由旧设备确认更换。旧设备确认与新设备证明都完成后，
// 更换在同一临界区内原子提交：家族绑定切换到新设备并立即轮换刷新令牌。
func (s *Service) ConfirmDeviceChange(req ConfirmChangeRequest) (*DeviceChangeOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	fam, ch, err := s.lookupChangeLocked(req.FamilyID, req.ChangeID, now)
	if err != nil {
		return nil, err
	}
	if ch.OldConfirmed {
		// 幂等：重复确认返回当前状态。
		return &DeviceChangeOutcome{Status: *changeStatus(ch, now)}, nil
	}
	// 确认必须来自家族当前绑定的（旧）设备。
	if req.DeviceID != fam.DeviceID || keyDigest(req.DevicePublicKey) != fam.DeviceKeyDigest {
		return nil, fmt.Errorf("tokenfamilies: family %s bound to another device: %w", fam.ID, ErrDeviceMismatch)
	}
	msg := DeviceChangeConfirmMessage(fam.ID, ch.ChangeID, ch.Nonce, ch.NewDeviceID, ch.NewKeyDigest)
	if !s.cfg.Verifier.Verify(req.DevicePublicKey, msg, req.Signature) {
		return nil, fmt.Errorf("tokenfamilies: family %s device proof rejected: %w", fam.ID, ErrInvalidDeviceProof)
	}
	ch.OldConfirmed = true
	s.recordEventLocked(fam, EventDeviceChangeOldConfirmed, "change_id="+ch.ChangeID, now)

	var pair *TokenPair
	if ch.NewProved {
		pair, err = s.commitDeviceChangeLocked(fam, ch, now)
		if err != nil {
			return nil, err
		}
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &DeviceChangeOutcome{Status: *changeStatus(ch, now), Tokens: pair}, nil
}

// ProveDeviceChange 由新设备证明持有登记公钥对应的私钥。
// 与旧设备确认汇合后原子提交更换（见 ConfirmDeviceChange）。
func (s *Service) ProveDeviceChange(req ProveChangeRequest) (*DeviceChangeOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock.Now()
	fam, ch, err := s.lookupChangeLocked(req.FamilyID, req.ChangeID, now)
	if err != nil {
		return nil, err
	}
	if ch.NewProved {
		// 幂等：重复证明返回当前状态。
		return &DeviceChangeOutcome{Status: *changeStatus(ch, now)}, nil
	}
	// 证明必须来自发起时登记的新设备。
	if req.DeviceID != ch.NewDeviceID || keyDigest(req.DevicePublicKey) != ch.NewKeyDigest {
		return nil, fmt.Errorf("tokenfamilies: proof does not match the registered new device: %w", ErrDeviceMismatch)
	}
	msg := DeviceChangeProveMessage(fam.ID, ch.ChangeID, ch.Nonce)
	if !s.cfg.Verifier.Verify(req.DevicePublicKey, msg, req.Signature) {
		return nil, fmt.Errorf("tokenfamilies: family %s device proof rejected: %w", fam.ID, ErrInvalidDeviceProof)
	}
	ch.NewProved = true
	s.recordEventLocked(fam, EventDeviceChangeNewProved, "change_id="+ch.ChangeID, now)

	var pair *TokenPair
	if ch.OldConfirmed {
		pair, err = s.commitDeviceChangeLocked(fam, ch, now)
		if err != nil {
			return nil, err
		}
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &DeviceChangeOutcome{Status: *changeStatus(ch, now), Tokens: pair}, nil
}

// lookupChangeLocked 定位更换流程并做公共检查（存在性、撤销、过期）。
// 已提交的流程也会正常返回，由调用方按幂等重放处理。
// 调用方必须持有 s.mu。
func (s *Service) lookupChangeLocked(familyID, changeID string, now time.Time) (*Family, *DeviceChange, error) {
	ch, ok := s.state.DeviceChanges[changeID]
	if !ok || ch.FamilyID != familyID {
		return nil, nil, fmt.Errorf("tokenfamilies: device change %q: %w", changeID, ErrChangeNotFound)
	}
	fam := s.state.Families[ch.FamilyID]
	if fam == nil {
		return nil, nil, fmt.Errorf("tokenfamilies: device change %q references missing family", changeID)
	}
	// 撤销优先：家族已撤销时，任何确认/证明都不得继续推进。
	if fam.Revoked {
		return nil, nil, fmt.Errorf("tokenfamilies: family %s revoked (%s): %w", fam.ID, fam.Reason, ErrFamilyRevoked)
	}
	if !ch.Committed && !now.Before(ch.ExpiresAt) {
		return nil, nil, fmt.Errorf("tokenfamilies: device change %q expired at %s: %w",
			changeID, ch.ExpiresAt.UTC().Format(time.RFC3339), ErrChangeExpired)
	}
	return fam, ch, nil
}

// resetChangeLocked 把已过期的更换流程重置为一次新尝试。
// 调用方必须持有 s.mu。
func (s *Service) resetChangeLocked(ch *DeviceChange, now time.Time) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	ch.Nonce = nonce
	ch.CreatedAt = now
	ch.ExpiresAt = now.Add(s.cfg.DeviceChangeTTL)
	ch.OldConfirmed = false
	ch.NewProved = false
	return nil
}

// commitDeviceChangeLocked 原子地把家族绑定切换到新设备并立即轮换刷新令牌。
// 提交前旧设备保持刷新资格，提交后仅新设备具备资格，不存在两者同时
// 具备资格的中间状态。调用方必须持有 s.mu，且已完成公共检查。
func (s *Service) commitDeviceChangeLocked(fam *Family, ch *DeviceChange, now time.Time) (*TokenPair, error) {
	// 让家族当前所有未消费的刷新令牌一次性失效（设备切换属于正常轮换，
	// 不判定重放）；随后签发的新一代令牌只有新设备能使用。
	generation := 1
	for _, rec := range s.state.RefreshTokens {
		if rec.FamilyID != fam.ID {
			continue
		}
		if rec.Generation+1 > generation {
			generation = rec.Generation + 1
		}
		if !rec.Consumed {
			rec.Consumed = true
			rec.ConsumedAt = &now
		}
	}
	fam.DeviceID = ch.NewDeviceID
	fam.DeviceKeyDigest = ch.NewKeyDigest
	fam.BindingVersion++
	fam.BoundAt = now
	ch.Committed = true
	ch.CommittedAt = &now

	pair, err := s.issueLocked(fam, generation, now)
	if err != nil {
		return nil, err
	}
	s.recordEventLocked(fam, EventDeviceChangeCommitted, "change_id="+ch.ChangeID, now)
	s.cfg.Logger.Info("device change committed",
		"family_id", fam.ID, "change_id", ch.ChangeID, "binding_version", fam.BindingVersion)
	return pair, nil
}

// DeviceChangeStatus 查询设备更换流程的进度。
func (s *Service) DeviceChangeStatus(familyID, changeID string) (*DeviceChangeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.state.DeviceChanges[changeID]
	if !ok || ch.FamilyID != familyID {
		return nil, fmt.Errorf("tokenfamilies: device change %q: %w", changeID, ErrChangeNotFound)
	}
	return changeStatus(ch, s.cfg.Clock.Now()), nil
}

// FamilyBinding 查询家族当前的设备绑定版本等信息。
func (s *Service) FamilyBinding(familyID string) (*BindingInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fam, ok := s.state.Families[familyID]
	if !ok {
		return nil, ErrFamilyNotFound
	}
	prefix := fam.DeviceKeyDigest
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return &BindingInfo{
		FamilyID:        fam.ID,
		DeviceID:        fam.DeviceID,
		BindingVersion:  fam.BindingVersion,
		KeyDigestPrefix: prefix,
		BoundAt:         fam.BoundAt,
		Revoked:         fam.Revoked,
	}, nil
}

// SecurityEvents 查询家族的安全事件（登录、轮换、撤销、设备更换等），
// 按发生顺序返回。事件中不包含令牌、公钥或签名等敏感值。
func (s *Service) SecurityEvents(familyID string) ([]SecurityEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.state.Families[familyID]; !ok {
		return nil, ErrFamilyNotFound
	}
	evs := s.state.Events[familyID]
	out := make([]SecurityEvent, len(evs))
	copy(out, evs)
	return out, nil
}

// changeStatus 由持久化记录构造进度视图。
func changeStatus(ch *DeviceChange, now time.Time) *DeviceChangeStatus {
	st := &DeviceChangeStatus{
		ChangeID:     ch.ChangeID,
		FamilyID:     ch.FamilyID,
		NewDeviceID:  ch.NewDeviceID,
		Nonce:        ch.Nonce,
		OldConfirmed: ch.OldConfirmed,
		NewProved:    ch.NewProved,
		CreatedAt:    ch.CreatedAt,
		ExpiresAt:    ch.ExpiresAt,
		CommittedAt:  ch.CommittedAt,
	}
	switch {
	case ch.Committed:
		st.Phase = PhaseCommitted
	case !now.Before(ch.ExpiresAt):
		st.Phase = PhaseExpired
	case !ch.OldConfirmed:
		st.Phase = PhasePendingOldConfirm
	default:
		st.Phase = PhasePendingNewProof
	}
	return st
}
