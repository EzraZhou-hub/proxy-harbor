// Package engine defines the boundary for a future verified native engine.
package engine

import (
	"context"
	"errors"
	"proxyharbor/internal/domain"
)

var ErrUnavailable = errors.New("保护内核尚未接入和验证，未启动应用、未设置代理或网络限制")

type Plan struct {
	Profile      domain.ProxyProfile
	Applications []domain.TargetApplication
}
type Adapter interface {
	Describe() domain.EngineStatus
	Prepare(context.Context, Plan) error
}
type Unavailable struct{}

func (Unavailable) Describe() domain.EngineStatus {
	return domain.EngineStatus{Name: "待接入代理内核", Available: false, Reason: "正在准备内核验证，当前未提供网络保护。"}
}
func (Unavailable) Prepare(context.Context, Plan) error { return ErrUnavailable }
