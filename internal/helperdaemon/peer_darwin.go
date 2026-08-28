//go:build darwin

package helperdaemon

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func authorizePeer(connection *net.UnixConn, ownerUID int) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errors.New("inspect helper peer")
	}
	var credential *unix.Xucred
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		credential, inspectErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return errors.New("inspect helper peer")
	}
	if inspectErr != nil || credential == nil || int(credential.Uid) != ownerUID {
		return errors.New("helper peer uid is unauthorized")
	}
	return nil
}
