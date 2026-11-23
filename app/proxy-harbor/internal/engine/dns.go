package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// DNSForwarder exchanges an opaque DNS message with an explicitly configured
// TCP resolver through Upstream. It never invokes the system resolver or UDP.
// This component is not an interceptor for the Windows DNS Client service.
type DNSForwarder struct {
	Upstream ProxyTransport
	Resolver string
	Timeout  time.Duration
}

func (d DNSForwarder) RoundTrip(ctx context.Context, query []byte) ([]byte, error) {
	if d.Upstream == nil {
		return nil, stageError("DNS", errors.New("缺少明确的代理传输"))
	}
	query = append([]byte(nil), query...)
	questionEnd, err := dnsQuestionEnd(query)
	if err != nil || len(query) > 65535 || query[2]&0xf8 != 0 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 {
		return nil, stageError("DNS", errors.New("DNS 请求无效；仅接受一个未压缩的标准 IN 查询"))
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.Upstream.DialContext(ctx, "tcp4", d.Resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, stageError("DNS", errors.New("无法设置解析超时"))
	}
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeAll(conn, frame); err != nil {
		return nil, stageError("DNS", errors.New("代理内 DNS 请求发送失败"))
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, stageError("DNS", errors.New("代理内 DNS 响应读取失败"))
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length < questionEnd {
		return nil, stageError("DNS", errors.New("DNS 响应长度无效"))
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, stageError("DNS", errors.New("DNS 响应不完整"))
	}
	// Preserve negative responses such as NXDOMAIN instead of retrying locally.
	// The question must match byte-for-byte; compressed questions are rejected.
	if !bytes.Equal(response[:2], query[:2]) || response[2]&0xfa != 0x80 ||
		binary.BigEndian.Uint16(response[4:6]) != 1 || !bytes.Equal(response[12:questionEnd], query[12:questionEnd]) {
		return nil, stageError("DNS", errors.New("DNS 响应标识、类型或问题不匹配"))
	}
	return response, nil
}

func dnsQuestionEnd(message []byte) (int, error) {
	if len(message) < 17 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return 0, errors.New("invalid question count")
	}
	position := 12
	for {
		if position >= len(message) || position-12 >= 255 {
			return 0, errors.New("invalid DNS name")
		}
		length := int(message[position])
		position++
		if length == 0 {
			break
		}
		if length > 63 || position+length >= len(message) {
			return 0, errors.New("compressed or incomplete question")
		}
		position += length
	}
	if position+4 > len(message) || binary.BigEndian.Uint16(message[position:position+2]) == 0 || binary.BigEndian.Uint16(message[position+2:position+4]) != 1 {
		return 0, errors.New("invalid question class or type")
	}
	return position + 4, nil
}
