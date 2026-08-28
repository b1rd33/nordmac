// Package helperproto defines the narrow, versioned boundary between the
// unprivileged CLI and a future privileged helper. It performs no IPC itself.
package helperproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const (
	SchemaVersion        = 2
	SecretChannelVersion = 1
	SecretFrameBytes     = 68
	maxRequestBytes      = 64 << 10
)

var secretMagic = [4]byte{'N', 'M', 'S', '1'}

type Operation string

const (
	OperationConnect    Operation = "connect"
	OperationDisconnect Operation = "disconnect"
	OperationRecover    Operation = "recover"
	OperationStatus     Operation = "status"
)

// Request contains no private key, bearer token, shell command, executable
// path, hook, or arbitrary file path. Connect secrets travel in the separate
// fixed binary frame defined below.
type Request struct {
	SchemaVersion        int          `json:"schema_version"`
	RequestID            string       `json:"request_id"`
	Operation            Operation    `json:"operation"`
	SessionID            string       `json:"session_id"`
	OwnerUID             int          `json:"owner_uid"`
	SecretChannelVersion int          `json:"secret_channel_version,omitempty"`
	Plan                 *tunnel.Plan `json:"plan,omitempty"`
}

func (request Request) Validate() error {
	if request.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported helper protocol schema %d", request.SchemaVersion)
	}
	if !tunnel.ValidSessionID(request.RequestID) || !tunnel.ValidSessionID(request.SessionID) || request.OwnerUID < 0 {
		return errors.New("invalid helper request identity")
	}
	switch request.Operation {
	case OperationConnect:
		if request.SecretChannelVersion != SecretChannelVersion || request.Plan == nil {
			return errors.New("connect requires the supported secret channel and a plan")
		}
		if err := request.Plan.Validate(); err != nil {
			return fmt.Errorf("invalid helper connect plan: %w", err)
		}
		if request.Plan.SessionID != request.SessionID || request.Plan.OwnerUID != request.OwnerUID {
			return errors.New("helper request identity does not match its plan")
		}
	case OperationDisconnect, OperationRecover, OperationStatus:
		if request.Plan != nil || request.SecretChannelVersion != 0 {
			return errors.New("non-connect helper request must not contain a plan or secret channel")
		}
	default:
		return fmt.Errorf("unsupported helper operation %q", request.Operation)
	}
	return nil
}

// EncodeFrame writes a bounded length-prefixed request followed, for connect,
// by the fixed-size secret frame. It is suitable for pipes and Unix sockets
// because neither decoder may consume bytes belonging to the other.
func EncodeFrame(writer io.Writer, request Request, secrets *DeviceSecrets) error {
	if err := request.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return errors.New("encode helper request")
	}
	defer wipe(data)
	if len(data) > maxRequestBytes {
		return errors.New("helper request exceeds size limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	if _, err := writer.Write(size[:]); err != nil {
		return errors.New("write helper request length")
	}
	if _, err := writer.Write(data); err != nil {
		return errors.New("write helper request")
	}
	if request.Operation == OperationConnect {
		return WriteSecrets(writer, secrets)
	}
	if secrets != nil {
		return errors.New("non-connect helper request contains secrets")
	}
	return nil
}

func DecodeFrame(reader io.Reader) (Request, DeviceSecrets, error) {
	var size [4]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return Request{}, DeviceSecrets{}, errors.New("read helper request length")
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxRequestBytes {
		return Request{}, DeviceSecrets{}, errors.New("invalid helper request length")
	}
	data := make([]byte, int(length))
	defer wipe(data)
	if _, err := io.ReadFull(reader, data); err != nil {
		return Request{}, DeviceSecrets{}, errors.New("read complete helper request")
	}
	request, err := DecodeRequest(bytes.NewReader(data))
	if err != nil {
		return Request{}, DeviceSecrets{}, err
	}
	if request.Operation != OperationConnect {
		if err := requireEOF(reader); err != nil {
			return Request{}, DeviceSecrets{}, err
		}
		return request, DeviceSecrets{}, nil
	}
	secrets, err := readSecretsExact(reader)
	if err != nil {
		return Request{}, DeviceSecrets{}, err
	}
	if err := requireEOF(reader); err != nil {
		secrets.Wipe()
		return Request{}, DeviceSecrets{}, err
	}
	return request, secrets, nil
}

func requireEOF(reader io.Reader) error {
	var extra [1]byte
	if count, err := reader.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		return errors.New("helper frame contains trailing data")
	}
	return nil
}

type Response struct {
	SchemaVersion int          `json:"schema_version"`
	RequestID     string       `json:"request_id"`
	OK            bool         `json:"ok"`
	State         tunnel.Phase `json:"state,omitempty"`
	ErrorCode     ErrorCode    `json:"error_code,omitempty"`
}

type ErrorCode string

const (
	ErrorInvalidRequest     ErrorCode = "invalid_request"
	ErrorUnauthorizedCaller ErrorCode = "unauthorized_caller"
	ErrorConflict           ErrorCode = "conflict"
	ErrorTransition         ErrorCode = "transition"
	ErrorRollback           ErrorCode = "rollback"
	ErrorInternal           ErrorCode = "internal"
)

func DecodeRequest(reader io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxRequestBytes+1))
	if err != nil {
		return Request{}, errors.New("read helper request")
	}
	defer wipe(data)
	if len(data) > maxRequestBytes {
		return Request{}, errors.New("helper request exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, errors.New("decode helper request")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("helper request contains trailing data")
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

func (response Response) Validate() error {
	if response.SchemaVersion != SchemaVersion || !tunnel.ValidSessionID(response.RequestID) {
		return errors.New("invalid helper response identity")
	}
	if response.State != "" && !validResponseState(response.State) {
		return errors.New("invalid helper response state")
	}
	if response.OK {
		if response.ErrorCode != "" {
			return errors.New("successful helper response contains an error")
		}
		return nil
	}
	if !validErrorCode(response.ErrorCode) {
		return errors.New("failed helper response has an invalid error code")
	}
	return nil
}

func EncodeResponse(writer io.Writer, response Response) error {
	if err := response.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(response)
	if err != nil {
		return errors.New("encode helper response")
	}
	if len(data) > maxRequestBytes {
		return errors.New("helper response exceeds size limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	if _, err := writer.Write(size[:]); err != nil {
		return errors.New("write helper response length")
	}
	if _, err := writer.Write(data); err != nil {
		return errors.New("write helper response")
	}
	return nil
}

func DecodeResponse(reader io.Reader) (Response, error) {
	var size [4]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return Response{}, errors.New("read helper response length")
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxRequestBytes {
		return Response{}, errors.New("invalid helper response length")
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil {
		return Response{}, errors.New("read complete helper response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, errors.New("decode helper response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("helper response contains trailing data")
	}
	if err := response.Validate(); err != nil {
		return Response{}, err
	}
	return response, nil
}

func validResponseState(state tunnel.Phase) bool {
	switch state {
	case tunnel.PhaseDisconnected, tunnel.PhaseConnecting, tunnel.PhaseConnected, tunnel.PhaseDegraded,
		tunnel.PhaseDisconnecting, tunnel.PhaseRollbackRequired, tunnel.PhaseForeignConflict:
		return true
	default:
		return false
	}
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorInvalidRequest, ErrorUnauthorizedCaller, ErrorConflict, ErrorTransition, ErrorRollback, ErrorInternal:
		return true
	default:
		return false
	}
}

// DeviceSecrets is an ephemeral raw WireGuard key pair. It must never be JSON
// encoded or placed in the journal. Call Wipe as soon as device configuration
// completes.
type DeviceSecrets struct {
	ClientPrivateKey [32]byte
	PeerPublicKey    [32]byte
}

func (secrets *DeviceSecrets) Validate() error {
	if secrets == nil {
		return errors.New("WireGuard keys are missing")
	}
	if allZero(secrets.ClientPrivateKey[:]) || allZero(secrets.PeerPublicKey[:]) {
		return errors.New("WireGuard keys must not be zero")
	}
	if bytes.Equal(secrets.ClientPrivateKey[:], secrets.PeerPublicKey[:]) {
		return errors.New("WireGuard private and peer public keys must differ")
	}
	return nil
}

func (secrets *DeviceSecrets) Wipe() {
	for index := range secrets.ClientPrivateKey {
		secrets.ClientPrivateKey[index] = 0
	}
	for index := range secrets.PeerPublicKey {
		secrets.PeerPublicKey[index] = 0
	}
}

func WriteSecrets(writer io.Writer, secrets *DeviceSecrets) error {
	if err := secrets.Validate(); err != nil {
		return err
	}
	frame := make([]byte, SecretFrameBytes)
	defer wipe(frame)
	copy(frame[:4], secretMagic[:])
	copy(frame[4:36], secrets.ClientPrivateKey[:])
	copy(frame[36:68], secrets.PeerPublicKey[:])
	written, err := writer.Write(frame)
	if err != nil {
		return fmt.Errorf("write helper secret frame: %w", err)
	}
	if written != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

func ReadSecrets(reader io.Reader) (DeviceSecrets, error) {
	secrets, err := readSecretsExact(reader)
	if err != nil {
		return DeviceSecrets{}, err
	}
	var extra [1]byte
	if count, err := reader.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		secrets.Wipe()
		return DeviceSecrets{}, errors.New("helper secret channel contains trailing data")
	}
	return secrets, nil
}

func readSecretsExact(reader io.Reader) (DeviceSecrets, error) {
	frame := make([]byte, SecretFrameBytes)
	defer wipe(frame)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return DeviceSecrets{}, errors.New("read complete helper secret frame")
	}
	if !bytes.Equal(frame[:4], secretMagic[:]) {
		return DeviceSecrets{}, errors.New("invalid helper secret frame version")
	}
	var secrets DeviceSecrets
	copy(secrets.ClientPrivateKey[:], frame[4:36])
	copy(secrets.PeerPublicKey[:], frame[36:68])
	if err := secrets.Validate(); err != nil {
		secrets.Wipe()
		return DeviceSecrets{}, err
	}
	return secrets, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
