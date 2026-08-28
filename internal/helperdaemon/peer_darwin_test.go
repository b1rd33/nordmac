//go:build darwin

package helperdaemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorizePeerUsesKernelUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientChannel := make(chan *net.UnixConn, 1)
	errorChannel := make(chan error, 1)
	go func() {
		client, dialErr := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if dialErr != nil {
			errorChannel <- dialErr
			return
		}
		clientChannel <- client
	}()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	select {
	case err := <-errorChannel:
		t.Fatal(err)
	case client := <-clientChannel:
		defer client.Close()
	}
	if err := authorizePeer(server, os.Getuid()); err != nil {
		t.Fatalf("current uid rejected: %v", err)
	}
	if err := authorizePeer(server, os.Getuid()+1); err == nil {
		t.Fatal("foreign uid accepted")
	}
}
