package tokenfamilies

import (
	"sort"
	"time"
)

// EventView 是事件的查询视图。
type EventView struct {
	Seq        int64
	Type       string
	DeviceID   string
	Generation int
	Reason     string
	At         time.Time
}

// TokenView 是单个令牌的查询视图。只包含不可逆摘要与序号，
// 绝不包含令牌明文。
type TokenView struct {
	Digest     string
	Generation int
	Consumed   bool
	ExpiresAt  time.Time
	// InvalidatedByEvent 非零时表示该令牌因对应序号的重放事件而失效，
	// 可以把受影响的后续令牌定位到具体的重放事件。
	InvalidatedByEvent int64
}

// FamilyView 是令牌家族的查询视图，展示家族、当前序号、设备绑定、
// 撤销原因以及生命周期内的事件序列。
type FamilyView struct {
	FamilyID       string
	UserID         string
	DeviceID       string
	DeviceVersion  int
	Generation     int
	Revoked        bool
	Reason         string
	RevokedByEvent int64
	Events         []EventView
	RefreshTokens  []TokenView
	AccessTokens   []TokenView
}

// InspectFamily 返回家族的查询视图。视图中只包含摘要与序号，
// 不包含任何令牌明文。家族不存在时返回 ErrFamilyNotFound。
func (s *Service) InspectFamily(familyID string) (*FamilyView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fam, ok := s.state.Families[familyID]
	if !ok {
		return nil, ErrFamilyNotFound
	}
	view := &FamilyView{
		FamilyID:       fam.ID,
		UserID:         fam.UserID,
		DeviceID:       fam.DeviceID,
		DeviceVersion:  fam.DeviceVersion,
		Generation:     fam.Generation,
		Revoked:        fam.Revoked,
		Reason:         fam.Reason,
		RevokedByEvent: fam.RevokedByEvent,
	}
	for _, ev := range s.state.Events {
		if ev.FamilyID != familyID {
			continue
		}
		view.Events = append(view.Events, EventView{
			Seq:        ev.Seq,
			Type:       ev.Type,
			DeviceID:   ev.DeviceID,
			Generation: ev.Generation,
			Reason:     ev.Reason,
			At:         ev.At,
		})
	}
	for _, rec := range s.state.RefreshTokens {
		if rec.FamilyID != familyID {
			continue
		}
		view.RefreshTokens = append(view.RefreshTokens, TokenView{
			Digest:             rec.Digest,
			Generation:         rec.Generation,
			Consumed:           rec.Consumed,
			ExpiresAt:          rec.ExpiresAt,
			InvalidatedByEvent: rec.InvalidatedByEvent,
		})
	}
	for _, rec := range s.state.AccessTokens {
		if rec.FamilyID != familyID {
			continue
		}
		view.AccessTokens = append(view.AccessTokens, TokenView{
			Digest:             rec.Digest,
			Generation:         rec.Generation,
			ExpiresAt:          rec.ExpiresAt,
			InvalidatedByEvent: rec.InvalidatedByEvent,
		})
	}
	byGeneration := func(views []TokenView) {
		sort.Slice(views, func(i, j int) bool { return views[i].Generation < views[j].Generation })
	}
	byGeneration(view.RefreshTokens)
	byGeneration(view.AccessTokens)
	return view, nil
}
