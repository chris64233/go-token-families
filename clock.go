package tokenfamilies

import "time"

// Clock 提供统一的当前时间来源。过期判断与幂等重试窗口
// 都必须通过同一个 Clock 取值，避免不同代码路径时间口径不一致。
type Clock interface {
	Now() time.Time
}

// ClockFunc 把普通函数适配为 Clock，便于测试注入假时钟。
type ClockFunc func() time.Time

// Now 实现 Clock。
func (f ClockFunc) Now() time.Time { return f() }

// SystemClock 使用真实系统时间。
func SystemClock() Clock { return ClockFunc(time.Now) }
