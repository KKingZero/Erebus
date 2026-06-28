package erebuscli

import (
	"net"
	"time"
)

// GRPCReachable returns true if something is listening on addr.
func GRPCReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}