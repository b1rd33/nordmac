// Package helperclient invokes or contacts nordmac's fixed internal privileged
// mode without putting keys in argv, environment variables, or files.
package helperclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/b1rd33/nordmac/internal/helperproto"
)

type Client struct {
	Executable string
	Stderr     *os.File
}

func (client Client) Exchange(ctx context.Context, request helperproto.Request, secrets *helperproto.DeviceSecrets) (helperproto.Response, error) {
	if request.Operation != helperproto.OperationConnect {
		if response, err := client.socket(ctx, request); err == nil {
			return response, nil
		} else if request.Operation == helperproto.OperationStatus {
			return helperproto.Response{SchemaVersion: helperproto.SchemaVersion, RequestID: request.RequestID, OK: true}, nil
		}
	}
	return client.bootstrap(ctx, request, secrets)
}

func (client Client) socket(ctx context.Context, request helperproto.Request) (helperproto.Response, error) {
	path := filepath.Join("/var/run/nordmac", strconv.Itoa(request.OwnerUID)+".sock")
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return helperproto.Response{}, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := helperproto.EncodeFrame(connection, request, nil); err != nil {
		return helperproto.Response{}, err
	}
	if writer, ok := connection.(interface{ CloseWrite() error }); ok {
		if err := writer.CloseWrite(); err != nil {
			return helperproto.Response{}, err
		}
	}
	return helperproto.DecodeResponse(connection)
}

func (client Client) bootstrap(ctx context.Context, request helperproto.Request, secrets *helperproto.DeviceSecrets) (helperproto.Response, error) {
	executable := client.Executable
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return helperproto.Response{}, errors.New("locate nordmac executable")
		}
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || !filepath.IsAbs(resolved) {
		return helperproto.Response{}, errors.New("resolve nordmac executable")
	}
	command := exec.Command("/usr/bin/sudo", "--", resolved, "__helper")
	command.Stderr = client.Stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		return helperproto.Response{}, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return helperproto.Response{}, err
	}
	if err := command.Start(); err != nil {
		return helperproto.Response{}, fmt.Errorf("start privileged helper: %w", err)
	}
	if err := helperproto.EncodeFrame(stdin, request, secrets); err != nil {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return helperproto.Response{}, err
	}
	_ = stdin.Close()
	type result struct {
		response helperproto.Response
		err      error
	}
	resultChannel := make(chan result, 1)
	go func() {
		response, decodeErr := helperproto.DecodeResponse(stdout)
		resultChannel <- result{response: response, err: decodeErr}
	}()
	select {
	case <-ctx.Done():
		_ = command.Process.Kill()
		_ = command.Wait()
		return helperproto.Response{}, ctx.Err()
	case result := <-resultChannel:
		if result.err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return helperproto.Response{}, result.err
		}
		if request.Operation == helperproto.OperationConnect && result.response.OK {
			if err := command.Process.Release(); err != nil {
				return helperproto.Response{}, err
			}
			return result.response, nil
		}
		waitErr := command.Wait()
		if !result.response.OK {
			return result.response, fmt.Errorf("privileged helper rejected request: %s", result.response.ErrorCode)
		}
		return result.response, waitErr
	}
}

var _ interface {
	Exchange(context.Context, helperproto.Request, *helperproto.DeviceSecrets) (helperproto.Response, error)
} = Client{}
