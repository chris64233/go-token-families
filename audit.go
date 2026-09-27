package tokenfamilies

import "time"

// AuditEventType 是审计事件的类型。
type AuditEventType string

const (
	AuditLogin             AuditEventType = "login"
	AuditRefreshRotated    AuditEventType = "refresh_rotated"
	AuditRefreshIdempotent AuditEventType = "refresh_idempotent"
	AuditReplayDetected    AuditEventType = "replay_detected"
	AuditFamilyRevoked     AuditEventType = "family_revoked"
	AuditRefreshDenied     AuditEventType = "refresh_denied"
)

// AuditEvent 是一条审计日志。字段经过刻意限制：只允许出现家族 ID、
// 用户 ID、代数与原因等不可用于伪造身份的信息，绝不包含令牌明文或摘要。
type AuditEvent struct {
	Time       time.Time
	Type       AuditEventType
	FamilyID   string
	UserID     string
	Generation int
	Reason     string
}

// AuditLogger 接收服务产生的审计事件。
type AuditLogger interface {
	LogAudit(AuditEvent)
}

// AuditFunc 把普通函数适配为 AuditLogger。
type AuditFunc func(AuditEvent)

// LogAudit 调用底层函数。
func (f AuditFunc) LogAudit(e AuditEvent) { f(e) }
