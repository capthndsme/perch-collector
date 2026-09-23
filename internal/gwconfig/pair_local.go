package gwconfig

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

// The daemon's local socket for `perch-collector pair` (PairSocket, under
// /var/run, so it is gone after a reboot): one JSON request per
// connection, one JSON answer. Only the daemon's own user (root on
// OpenWrt) may use it: the socket is 0600 in a 0700 directory, and on
// Linux the peer's uid is checked as well (SO_PEERCRED). Confirming a
// pairing on the router is the step that proves the admin has a shell
// there; nothing reaches it over the network.

// PairRequest is a request on the local socket.
type PairRequest struct {
	// Cmd is status, confirm, reject or forget.
	Cmd  string `json:"cmd"`
	Code string `json:"code,omitempty"`
}

// PairResponse is the answer.
type PairResponse struct {
	OK     bool       `json:"ok"`
	Error  string     `json:"error,omitempty"`
	Status *PairLocal `json:"status,omitempty"`
	// Paired: the key a confirm stored, or the one a forget dropped.
	Paired *PairInfo `json:"paired,omitempty"`
}

// ServePairSocket listens on the plane's PairSocketPath until ctx ends.
func (p *Plane) ServePairSocket(ctx context.Context) error {
	path := p.PairSocketPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// The run directory also holds the apply markers: keep it private.
	_ = os.Chmod(dir, 0o700)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	uid := os.Geteuid()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				os.Remove(path)
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go p.servePairConn(conn, uid)
	}
}

func (p *Plane) servePairConn(conn net.Conn, uid int) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	enc := json.NewEncoder(conn)
	if peer, ok := peerUID(conn); ok && peer != uid {
		enc.Encode(PairResponse{Error: "only root can manage the pairing"})
		return
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req PairRequest
	if err := json.Unmarshal(line, &req); err != nil {
		enc.Encode(PairResponse{Error: "bad request"})
		return
	}
	enc.Encode(p.HandlePairRequest(req))
}

// HandlePairRequest runs one local request.
func (p *Plane) HandlePairRequest(req PairRequest) PairResponse {
	switch req.Cmd {
	case "status":
		return PairResponse{OK: true, Status: p.PairLocalStatus()}
	case "confirm":
		info, err := p.PairConfirmLocal(req.Code)
		if err != nil {
			return PairResponse{Error: err.Error(), Status: p.PairLocalStatus()}
		}
		return PairResponse{OK: true, Paired: info}
	case "reject":
		if err := p.PairRejectLocal(); err != nil {
			return PairResponse{Error: err.Error()}
		}
		log.Printf("config plane: pairing rejected on the router")
		return PairResponse{OK: true}
	case "forget":
		info, err := p.PairForgetLocal()
		if err != nil {
			return PairResponse{Error: err.Error()}
		}
		return PairResponse{OK: true, Paired: info}
	}
	return PairResponse{Error: fmt.Sprintf("unknown command %q", req.Cmd)}
}

// ErrNoDaemon: nothing listens on the local socket.
var ErrNoDaemon = errors.New("the perch-collector daemon is not running (or runs without the config plane)")

// PairCall sends one request to the daemon's socket at path.
func PairCall(path string, req PairRequest) (*PairResponse, error) {
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, os.ErrPermission) {
			return nil, errors.New("permission denied: run it as root")
		}
		return nil, ErrNoDaemon
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, err
	}
	var res PairResponse
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return nil, fmt.Errorf("reading the daemon's answer: %w", err)
	}
	return &res, nil
}
