package wgbackend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/tunnel"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type UserspaceFactory struct{}

func (UserspaceFactory) Create(mtu int) (Runtime, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("the nordmac userspace backend requires macOS")
	}
	tunDevice, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, err
	}
	name, err := tunDevice.Name()
	if err != nil {
		_ = tunDevice.Close()
		return nil, err
	}
	wgDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	return &userspaceRuntime{name: name, device: wgDevice}, nil
}

type userspaceRuntime struct {
	name   string
	device *device.Device
	once   sync.Once
}

func (wireguard *userspaceRuntime) Name() string { return wireguard.name }

func (wireguard *userspaceRuntime) Configure(spec tunnel.DeviceSpec, secrets *helperproto.DeviceSecrets) error {
	configuration := make([]byte, 0, 320)
	defer func() { wipe(configuration) }()
	configuration = append(configuration, "private_key="...)
	configuration = hex.AppendEncode(configuration, secrets.ClientPrivateKey[:])
	configuration = append(configuration, '\n')
	configuration = append(configuration, "replace_peers=true\npublic_key="...)
	configuration = hex.AppendEncode(configuration, secrets.PeerPublicKey[:])
	configuration = append(configuration, '\n')
	configuration = append(configuration, "endpoint="...)
	configuration = append(configuration, spec.Endpoint.String()...)
	configuration = append(configuration, "\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n\n"...)
	if err := wireguard.device.IpcSetOperation(bytes.NewReader(configuration)); err != nil {
		return err
	}
	return nil
}

func (wireguard *userspaceRuntime) Up() error { return wireguard.device.Up() }

func (wireguard *userspaceRuntime) Snapshot() (Snapshot, error) {
	var output bytes.Buffer
	defer func() { wipe(output.Bytes()) }()
	if err := wireguard.device.IpcGetOperation(&output); err != nil {
		return Snapshot{}, err
	}
	return parseSnapshot(output.Bytes())
}

func (wireguard *userspaceRuntime) Close() error {
	wireguard.once.Do(func() { wireguard.device.Close() })
	return nil
}

func parseSnapshot(configuration []byte) (Snapshot, error) {
	var snapshot Snapshot
	var seconds, nanoseconds int64
	foundPeer := false
	for _, rawLine := range bytes.Split(configuration, []byte{'\n'}) {
		rawKey, rawValue, ok := bytes.Cut(rawLine, []byte{'='})
		if !ok {
			continue
		}
		// Never materialize the private_key line as a Go string. wireguard-go's
		// UAPI includes it in get responses even though this parser needs only
		// peer counters.
		if bytes.Equal(rawKey, []byte("private_key")) {
			continue
		}
		key, value := string(rawKey), string(rawValue)
		var err error
		switch key {
		case "public_key":
			foundPeer = true
		case "last_handshake_time_sec":
			seconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, err = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			snapshot.Transmitted, err = strconv.ParseUint(value, 10, 64)
		case "rx_bytes":
			snapshot.Received, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return Snapshot{}, fmt.Errorf("parse WireGuard %s: %w", key, err)
		}
	}
	if !foundPeer {
		return Snapshot{}, errors.New("WireGuard runtime has no configured peer")
	}
	if seconds > 0 {
		snapshot.LastHandshake = time.Unix(seconds, nanoseconds)
	}
	return snapshot, nil
}

func wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
