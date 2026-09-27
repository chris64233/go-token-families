package tokenfamilies

import (
	"sync"
	"time"
)

// Clock 是服务内所有时间判断（过期、幂等窗口、撤销时间）的统一时间来源。
type Clock interface {
	Now() time.Time
}

// SystemClock 使用真实系统时间。
type SystemClock struct{}

// Now 返回当前系统时间。
func (SystemClock) Now() time.Time { return time.Now() }

// ManualClock 是可手动推进的时钟，主要用于测试。
type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewManualClock 创建一个从 t 开始的 ManualClock。
func NewManualClock(t time.Time) *ManualClock {
	return &ManualClock{now: t}
}

// Now 返回当前时钟时间。
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 将时钟向前推进 d。
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set 将时钟设置为 t。
func (c *ManualClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}
