package tokenfamilies

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DeviceBinding 是家族当前绑定的设备信息。
// 其中只保存设备标识与公钥摘要，绝不保存公钥本身、私钥或原始证明材料。
type DeviceBinding struct {
	// DeviceID 是设备的稳定标识。
	DeviceID string `json:"device_id"`
	// PublicKeyDigest 是设备公钥的 SHA-256 摘要。
	PublicKeyDigest string `json:"public_key_digest"`
	// BoundAt 是本次绑定（含换绑）生效的时刻。
	BoundAt time.Time `json:"bound_at"`
}

// Family 表示一次登录创建的令牌家族。
type Family struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	// Binding 是家族当前绑定的设备；每次成功换绑都会整体替换。
	Binding DeviceBinding `json:"binding"`
	// BindingVersion 是设备绑定版本，登录时为 1，每次成功更换设备 +1。
	// 每个令牌记录签发时的绑定版本；访问令牌校验必须反映当前版本。
	BindingVersion int        `json:"binding_version"`
	Revoked        bool       `json:"revoked"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	// Reason 记录撤销原因（"manual" / "replay"），便于审计。
	Reason string `json:"reason,omitempty"`
}

// RefreshTokenRecord 是刷新令牌的持久化记录，以摘要为键。
type RefreshTokenRecord struct {
	Digest     string `json:"digest"`
	FamilyID   string `json:"family_id"`
	Generation int    `json:"generation"`
	// BindingVersion 是该令牌签发时家族的设备绑定版本。
	// 换绑后旧版本令牌即使用户令牌本身未消耗，也不再具备刷新资格。
	BindingVersion int        `json:"binding_version"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Consumed       bool       `json:"consumed"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	// ConsumeReason 记录一次性失效原因："rotation"（普通轮换）/
	// "device_change"（设备更换时原子轮换）。
	ConsumeReason string `json:"consume_reason,omitempty"`
}

// AccessTokenRecord 是访问令牌的持久化记录，以摘要为键。
type AccessTokenRecord struct {
	Digest   string `json:"digest"`
	FamilyID string `json:"family_id"`
	UserID   string `json:"user_id"`
	// BindingVersion 是该访问令牌签发时家族的设备绑定版本。
	BindingVersion int       `json:"binding_version"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// 设备更换流程的状态常量。
const (
	changePending   = "pending"   // 已发起，等待双方确认/证明
	changeCompleted = "completed" // 双方齐备，已原子换绑并轮换
)

// DeviceChangeRecord 是一次受控设备更换流程的持久化记录。
// 不包含任何令牌明文、公钥本身、私钥、签名或原始证明材料；
// 新设备只以公钥摘要形式出现，挑战值是服务端生成的随机一次性值（非秘密，
// 但仅在短期有效期内有意义，过期即作废）。
type DeviceChangeRecord struct {
	ID             string     `json:"id"`
	FamilyID       string     `json:"family_id"`
	EventID        string     `json:"event_id"`
	BindingVersion int        `json:"binding_version"`
	OldDeviceID    string     `json:"old_device_id"`
	OldKeyDigest   string     `json:"old_key_digest"`
	NewDeviceID    string     `json:"new_device_id"`
	NewKeyDigest   string     `json:"new_key_digest"`
	Challenge      string     `json:"challenge"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	OldConfirmedAt *time.Time `json:"old_confirmed_at,omitempty"`
	NewProvedAt    *time.Time `json:"new_proved_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	// NewGeneration 是换绑后原子轮换出的刷新令牌世代，仅用于审计展示。
	NewGeneration int `json:"new_generation,omitempty"`
}

// SecurityEvent 是一条安全审计事件。所有字段均为非敏感值：
// 只含家族/设备标识、绑定版本、枚举化的事件类型与非敏感细节，
// 绝不含令牌明文、密钥材料、签名或原始证明材料。
type SecurityEvent struct {
	ID             string            `json:"id"`
	FamilyID       string            `json:"family_id"`
	Type           string            `json:"type"`
	At             time.Time         `json:"at"`
	BindingVersion int               `json:"binding_version"`
	Detail         map[string]string `json:"detail,omitempty"`
}

// 安全事件类型。
const (
	EventLogin              = "login"
	EventRefresh            = "refresh"
	EventManualRevoke       = "manual_revoke"
	EventReplayRevoke       = "replay_revoke"
	EventChangeInitiated    = "device_change_initiated"
	EventChangeOldConfirmed = "device_change_old_confirmed"
	EventChangeNewProved    = "device_change_new_proved"
	EventChangeCompleted    = "device_change_completed"
	EventChangeReplay       = "device_change_replay"
)

// maxEventsPerFamily 限制每个家族保留的安全事件数量，超出时丢弃最旧的事件。
const maxEventsPerFamily = 100

// State 是服务的全部持久化状态。其中只包含令牌/公钥摘要，不包含任何明文密钥材料。
type State struct {
	Families      map[string]*Family             `json:"families"`
	RefreshTokens map[string]*RefreshTokenRecord `json:"refresh_tokens"`
	AccessTokens  map[string]*AccessTokenRecord  `json:"access_tokens"`
	// DeviceChanges 以流程 ID 为键保存更换流程（含已完成的历史流程）。
	DeviceChanges map[string]*DeviceChangeRecord `json:"device_changes"`
	// SecurityEvents 按家族保存安全事件（每个家族仅保留最近 maxEventsPerFamily 条）。
	SecurityEvents map[string][]*SecurityEvent `json:"security_events"`
}

func newState() *State {
	return &State{
		Families:       make(map[string]*Family),
		RefreshTokens:  make(map[string]*RefreshTokenRecord),
		AccessTokens:   make(map[string]*AccessTokenRecord),
		DeviceChanges:  make(map[string]*DeviceChangeRecord),
		SecurityEvents: make(map[string][]*SecurityEvent),
	}
}

// clone 通过 JSON 往返做一次深拷贝，避免 Store 与 Service 共享可变指针。
func (s *State) clone() (*State, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("tokenfamilies: clone state: %w", err)
	}
	var out State
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("tokenfamilies: clone state: %w", err)
	}
	return &out, nil
}

// Store 是持久化层接口。实现必须保证 Save 后状态可恢复。
// 注意：State 中只应包含不可逆摘要，任何实现都不应扩展它来保存令牌明文。
type Store interface {
	Load() (*State, error)
	Save(state *State) error
}

// MemoryStore 是内存 Store 实现，主要用于测试与嵌入式场景。
type MemoryStore struct {
	mu    sync.Mutex
	state *State
}

// NewMemoryStore 创建一个空的内存 Store。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{state: newState()}
}

// Load 返回当前状态的深拷贝。
func (m *MemoryStore) Load() (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.clone()
}

// Save 以深拷贝方式保存状态。
func (m *MemoryStore) Save(state *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := state.clone()
	if err != nil {
		return err
	}
	m.state = c
	return nil
}

// FileStore 以 JSON 文件持久化状态，写入采用临时文件 + 原子重命名。
// 文件中只包含摘要与元数据，不包含令牌明文。
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore 创建基于指定路径的文件 Store。
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Load 读取状态文件；文件不存在时返回空状态。
func (f *FileStore) Load() (*State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("tokenfamilies: load state file: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("tokenfamilies: parse state file: %w", err)
	}
	if st.Families == nil {
		st.Families = make(map[string]*Family)
	}
	if st.RefreshTokens == nil {
		st.RefreshTokens = make(map[string]*RefreshTokenRecord)
	}
	if st.AccessTokens == nil {
		st.AccessTokens = make(map[string]*AccessTokenRecord)
	}
	if st.DeviceChanges == nil {
		st.DeviceChanges = make(map[string]*DeviceChangeRecord)
	}
	if st.SecurityEvents == nil {
		st.SecurityEvents = make(map[string][]*SecurityEvent)
	}
	return &st, nil
}

// Save 将状态原子写入文件。
func (f *FileStore) Save(state *State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("tokenfamilies: marshal state: %w", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("tokenfamilies: write state file: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("tokenfamilies: commit state file: %w", err)
	}
	return nil
}

// Path 返回底层文件路径（主要用于测试断言文件内容）。
func (f *FileStore) Path() string { return f.path }

// Dir 创建文件所在目录（便捷方法，供使用前调用）。
func (f *FileStore) MkdirAll() error {
	return os.MkdirAll(filepath.Dir(f.path), 0o700)
}
