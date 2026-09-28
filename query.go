package tokenfamilies

import (
	"sort"
	"time"
)

// 刷新令牌一次性失效的原因。
const (
	consumeReasonRotation     = "rotation"
	consumeReasonDeviceChange = "device_change"
)

// 对外可见的更换流程状态。
const (
	StatusPending   = "pending"
	StatusCompleted = "completed"
	StatusExpired   = "expired"
)

// DeviceChangeStatus 是设备更换流程的对外只读视图。
// 所有字段均为非敏感值：不含令牌明文、密钥材料、签名或原始证明材料，
// 挑战值只在流程待处理且未过期时返回（设备需要用它构造签名）。
type DeviceChangeStatus struct {
	ID             string `json:"id"`
	FamilyID       string `json:"family_id"`
	EventID        string `json:"event_id"`
	BindingVersion int    `json:"binding_version"`
	OldDeviceID    string `json:"old_device_id"`
	NewDeviceID    string `json:"new_device_id"`
	Status         string `json:"status"` // pending / completed / expired
	OldConfirmed   bool   `json:"old_confirmed"`
	NewProved      bool   `json:"new_proved"`
	CreatedAt      string `json:"created_at"`             // RFC3339（UTC）
	ExpiresAt      string `json:"expires_at"`             // RFC3339（UTC）
	CompletedAt    string `json:"completed_at,omitempty"` // RFC3339（UTC），未完成时为空
	Challenge      string `json:"challenge,omitempty"`    // 仅待处理流程返回
	NewBindingVer  int    `json:"new_binding_version,omitempty"`
	NewGeneration  int    `json:"new_generation,omitempty"`
}

// FamilyBindingInfo 是家族当前设备绑定的对外只读视图。
// 只含设备标识，不含公钥摘要以外的任何密钥材料（公钥摘要亦不返回，避免不必要扩散）。
type FamilyBindingInfo struct {
	FamilyID       string `json:"family_id"`
	UserID         string `json:"user_id"`
	DeviceID       string `json:"device_id"`
	BindingVersion int    `json:"binding_version"`
	BoundAt        string `json:"bound_at"` // RFC3339（UTC）
	Revoked        bool   `json:"revoked"`
	Reason         string `json:"reason,omitempty"`
}

// SecurityEventView 是安全事件的对外只读视图，字段全部为非敏感值。
type SecurityEventView struct {
	ID             string            `json:"id"`
	Type           string            `json:"type"`
	At             string            `json:"at"` // RFC3339（UTC）
	BindingVersion int               `json:"binding_version"`
	Detail         map[string]string `json:"detail,omitempty"`
}

// statusOfLocked 由持久化记录构造脱敏的状态视图。调用方必须持有 s.mu。
func (s *Service) statusOfLocked(rec *DeviceChangeRecord, now time.Time) *DeviceChangeStatus {
	status := rec.Status
	out := &DeviceChangeStatus{
		ID:             rec.ID,
		FamilyID:       rec.FamilyID,
		EventID:        rec.EventID,
		BindingVersion: rec.BindingVersion,
		OldDeviceID:    rec.OldDeviceID,
		NewDeviceID:    rec.NewDeviceID,
		Status:         status,
		OldConfirmed:   rec.OldConfirmedAt != nil,
		NewProved:      rec.NewProvedAt != nil,
		CreatedAt:      rec.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:      rec.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if status == changePending {
		if !now.Before(rec.ExpiresAt) {
			out.Status = StatusExpired
		} else {
			// 挑战只对仍可确认的待处理流程可见。
			out.Challenge = rec.Challenge
		}
	}
	if rec.CompletedAt != nil {
		out.CompletedAt = rec.CompletedAt.UTC().Format(time.RFC3339)
		out.NewBindingVer = rec.BindingVersion + 1
		out.NewGeneration = rec.NewGeneration
	}
	return out
}

// GetDeviceChange 按流程 ID 查询设备更换进度。返回内容已脱敏。
func (s *Service) GetDeviceChange(changeID string) (*DeviceChangeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.DeviceChanges[changeID]
	if !ok {
		return nil, ErrChangeNotFound
	}
	return s.statusOfLocked(rec, s.cfg.Clock.Now()), nil
}

// GetDeviceChangeByEvent 按家族 + 更换事件 ID 查询最近一次更换进度。
func (s *Service) GetDeviceChangeByEvent(familyID, eventID string) (*DeviceChangeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.findChangeByEventLocked(familyID, eventID)
	if rec == nil {
		return nil, ErrChangeNotFound
	}
	return s.statusOfLocked(rec, s.cfg.Clock.Now()), nil
}

// GetActiveDeviceChange 返回家族当前未过期的待处理更换流程；不存在时返回
// ErrChangeNotFound（包括流程已完成或已过期的情况）。
func (s *Service) GetActiveDeviceChange(familyID string) (*DeviceChangeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Families[familyID]; !ok {
		return nil, ErrFamilyNotFound
	}
	now := s.cfg.Clock.Now()
	var found *DeviceChangeRecord
	for _, rec := range s.state.DeviceChanges {
		if rec.FamilyID != familyID || rec.Status != changePending || !now.Before(rec.ExpiresAt) {
			continue
		}
		if found == nil || rec.CreatedAt.After(found.CreatedAt) {
			found = rec
		}
	}
	if found == nil {
		return nil, ErrChangeNotFound
	}
	return s.statusOfLocked(found, now), nil
}

// GetFamilyBinding 查询家族当前绑定的设备标识与绑定版本。
func (s *Service) GetFamilyBinding(familyID string) (*FamilyBindingInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fam, ok := s.state.Families[familyID]
	if !ok {
		return nil, ErrFamilyNotFound
	}
	return &FamilyBindingInfo{
		FamilyID:       fam.ID,
		UserID:         fam.UserID,
		DeviceID:       fam.Binding.DeviceID,
		BindingVersion: fam.BindingVersion,
		BoundAt:        fam.Binding.BoundAt.UTC().Format(time.RFC3339),
		Revoked:        fam.Revoked,
		Reason:         fam.Reason,
	}, nil
}

// ListSecurityEvents 返回家族的安全事件列表（按时间正序）。
// 返回内容只含枚举事件类型、绑定版本与非敏感标识，绝不包含令牌/密钥材料。
func (s *Service) ListSecurityEvents(familyID string) ([]SecurityEventView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Families[familyID]; !ok {
		return nil, ErrFamilyNotFound
	}
	events := s.state.SecurityEvents[familyID]
	out := make([]SecurityEventView, 0, len(events))
	for _, ev := range events {
		view := SecurityEventView{
			ID:             ev.ID,
			Type:           ev.Type,
			At:             ev.At.UTC().Format(time.RFC3339),
			BindingVersion: ev.BindingVersion,
		}
		if len(ev.Detail) > 0 {
			view.Detail = make(map[string]string, len(ev.Detail))
			for k, v := range ev.Detail {
				view.Detail[k] = v
			}
		}
		out = append(out, view)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out, nil
}
