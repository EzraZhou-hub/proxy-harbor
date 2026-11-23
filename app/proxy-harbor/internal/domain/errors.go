package domain

import "errors"

var (
	ErrInvalidConfig = errors.New("配置文件无效")
	ErrConfigChanged = errors.New("配置已被其他窗口或程序修改，请重新读取配置后重试")
)
