//go:build !darwin

package helperdaemon

import (
	"errors"
	"net"
)

func authorizePeer(*net.UnixConn, int) error {
	return errors.New("privileged helper peer authentication requires macOS")
}
