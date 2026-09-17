// termprobe：出口终端服务的独立探针（开发/排障用；不进 Release）。
// 用法：go run ./cmd/termprobe <tc-addr> [--kill <name>]
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tailscale/tailcat"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: termprobe <tc-addr>")
		os.Exit(2)
	}
	cl := &tailcat.Client{Server: tailcat.Addr(os.Args[1])}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := cl.DialTCPPort(ctx, 7724)
	if err != nil {
		fmt.Println("dial err:", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	op, payload, err := frame(conn)
	fmt.Printf("greeting op=0x%02x len=%d err=%v\n", op, len(payload), err)
	if err != nil {
		return
	}
	// LIST
	if _, err := conn.Write([]byte{0x04, 0, 0}); err != nil {
		fmt.Println("list write err:", err)
		return
	}
	op2, pl2, err := frame(conn)
	fmt.Printf("reply op=0x%02x err=%v\n%s\n", op2, err, string(pl2))
}

func frame(r io.Reader) (byte, []byte, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.LittleEndian.Uint16(h[1:3]))
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
	}
	return h[0], buf, nil
}
