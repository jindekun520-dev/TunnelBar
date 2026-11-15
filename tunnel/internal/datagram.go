package internal

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxDatagram 单条 UDP 数据报的上限。TUN 的 MTU 一般不超过 1500，
// 8192 已足够覆盖 4~6 千字节的普通 UDP 报文。
const MaxDatagram = 8192

var (
	// ErrDatagramTooLarge 数据报超过 MaxDatagram。
	ErrDatagramTooLarge = errors.New("tunnel: 数据报过大")
	// ErrDatagramCorrupt 长度前缀与实际数据不匹配。
	ErrDatagramCorrupt = errors.New("tunnel: 数据报分帧损坏")
)

// WriteDatagram 把一条 UDP 数据报按 [2B 长度][数据] 写入流。
//
// 复用流本身是字节流，没有消息边界，UDP 只能靠长度前缀自行分帧。
func WriteDatagram(w io.Writer, b []byte) error {
	if len(b) > MaxDatagram {
		return ErrDatagramTooLarge
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(b)))
	copy(buf[2:], b)
	_, err := w.Write(buf)
	return err
}

// ReadDatagram 读出一条 UDP 数据报。返回的切片每次新分配，可安全持有。
func ReadDatagram(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > MaxDatagram {
		return nil, ErrDatagramTooLarge
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, ErrDatagramCorrupt
	}
	return buf, nil
}
