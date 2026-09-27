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

// Family 表示一次登录创建的令牌家族。
type Family struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// Reason 记录撤销原因（"manual" / "replay"），便于审计。
	Reason string `json:"reason,omitempty"`
}

// RefreshTokenRecord 是刷新令牌的持久化记录，以摘要为键。
type RefreshTokenRecord struct {
	Digest     string     `json:"digest"`
	FamilyID   string     `json:"family_id"`
	Generation int        `json:"generation"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Consumed   bool       `json:"consumed"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// AccessTokenRecord 是访问令牌的持久化记录，以摘要为键。
type AccessTokenRecord struct {
	Digest    string    `json:"digest"`
	FamilyID  string    `json:"family_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// State 是服务的全部持久化状态。其中只包含令牌摘要，不包含任何令牌明文。
type State struct {
	Families      map[string]*Family             `json:"families"`
	RefreshTokens map[string]*RefreshTokenRecord `json:"refresh_tokens"`
	AccessTokens  map[string]*AccessTokenRecord  `json:"access_tokens"`
}

func newState() *State {
	return &State{
		Families:      make(map[string]*Family),
		RefreshTokens: make(map[string]*RefreshTokenRecord),
		AccessTokens:  make(map[string]*AccessTokenRecord),
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
