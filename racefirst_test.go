// racefirst_test.go — 赛跑核心 raceFirst 的单测（openspec
// direct-handshake-connect，2026-09-17 二轮 review 补）。
//
// 意义：整个「直连优先就绪」的决策都收在 raceFirst 一个纯逻辑函数里，但修复
// 后没有任何用例能证明探针那条腿（TestDirectMinimal 只断言 readyBy ∈
// {direct,meow}，meow 赢就通过）。这里注入假探针/假 meow 通道，把四条路径
// 都钉住——尤其是第一条：**探针在飞期间 meow 到达必须立刻就绪**（第一版把
// probe 同步写在循环体里，meow 只能等探针窗口结束才被观察到，最坏白等 1s）。
package tailcat

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// meowAfter 返回一个在 d 之后关闭的 meow 通道（模拟 meowed 到达）。
func meowAfter(d time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		time.Sleep(d)
		close(ch)
	}()
	return ch
}

// neverMeow 永不关闭：用不到 meow 腿的用例。
func neverMeow() <-chan struct{} { return make(chan struct{}) }

func TestRaceFirstMeowPreemptsInFlightProbe(t *testing.T) {
	var calls atomic.Int32
	// 在飞的探针：500ms 才失败（远长于 meow 的 10ms）。
	probe := func(ctx context.Context) error {
		calls.Add(1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		return errors.New("probe miss")
	}

	t0 := time.Now()
	by, err := raceFirst(context.Background(), meowAfter(10*time.Millisecond), probe, 3, time.Second, nil)
	elapsed := time.Since(t0)
	if err != nil || by != "meow" {
		t.Fatalf("by=%q err=%v; want meow", by, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("meow 等了 %v 才被认出来（应 <100ms）：赛跑退化成「探针优先」", elapsed)
	}

	// 返回后探针必须立刻收工（defer cancel），否则就绪了还在往隧道里打探针。
	time.Sleep(50 * time.Millisecond) // 让在飞的那次探针收尾
	settled := calls.Load()
	time.Sleep(80 * time.Millisecond)
	if got := calls.Load(); got != settled {
		t.Errorf("raceFirst 返回后探针又被调用了（%d→%d）：cancel 没生效", settled, got)
	}
}

func TestRaceFirstProbeWins(t *testing.T) {
	by, err := raceFirst(context.Background(), neverMeow(), func(context.Context) error { return nil }, 3, time.Millisecond, nil)
	if err != nil || by != "direct" {
		t.Fatalf("by=%q err=%v; want direct", by, err)
	}
}

func TestRaceFirstProbeSucceedsOnRetry(t *testing.T) {
	var calls atomic.Int32
	probe := func(context.Context) error {
		if calls.Add(1) < 3 {
			return errors.New("probe miss")
		}
		return nil
	}
	by, err := raceFirst(context.Background(), neverMeow(), probe, 3, time.Millisecond, nil)
	if err != nil || by != "direct" {
		t.Fatalf("by=%q err=%v; want direct", by, err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("probe calls = %d; want 3", n)
	}
}

// 探针用尽 attempts 后出局：回调一行（诊断日志用）、不再继续探、meow 仍被等到。
func TestRaceFirstProbeExhaustedThenMeow(t *testing.T) {
	var calls atomic.Int32
	var exhausted atomic.Bool
	probe := func(context.Context) error { calls.Add(1); return errors.New("probe miss") }

	by, err := raceFirst(context.Background(), meowAfter(120*time.Millisecond), probe, 2, 10*time.Millisecond, func() {
		exhausted.Store(true)
	})
	if err != nil || by != "meow" {
		t.Fatalf("by=%q err=%v; want meow", by, err)
	}
	if !exhausted.Load() {
		t.Error("探针腿出局时未回调（诊据日志会缺「未成→meow」那一行）")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("probe calls = %d; want 2（出局后不应再探）", n)
	}
}

func TestRaceFirstCtxDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	_, err := raceFirst(ctx, neverMeow(), func(context.Context) error { return errors.New("probe miss") }, 3, 10*time.Millisecond, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want DeadlineExceeded（旧路径语义：无条件等 meowed 到调用方超时）", err)
	}
}
