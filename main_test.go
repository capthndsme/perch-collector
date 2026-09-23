package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"
)

// writeTree creates files (path → content) under a temporary root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// routerInAContainer is a gateway whose ports are the inside ends of veths:
// wan0 holds the default route, lan0 does not; lo and the SQM ifb are no
// ports.
func routerInAContainer() map[string]string {
	files := map[string]string{
		"proc/net/route": "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
			"wan0\t00000000\t017100CB\t0003\t0\t0\t1\t00000000\t0\t0\t0\n" +
			"lan0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
	}
	netdev := func(name string, attrs map[string]string) {
		for k, v := range attrs {
			files["sys/class/net/"+name+"/"+k] = v + "\n"
		}
	}
	netdev("lo", map[string]string{"type": "772", "ifindex": "1", "iflink": "1", "flags": "0x9"})
	netdev("ifb4wan0", map[string]string{"type": "1", "ifindex": "22", "iflink": "22", "flags": "0x83"})
	netdev("lan0", map[string]string{"type": "1", "ifindex": "29", "iflink": "30", "flags": "0x1003", "carrier": "1",
		"carrier_changes": "2", "operstate": "up", "speed": "10000", "duplex": "full", "address": "02:00:00:00:00:29"})
	netdev("wan0", map[string]string{"type": "1", "ifindex": "35", "iflink": "36", "flags": "0x1003", "carrier": "0",
		"carrier_changes": "3", "operstate": "lowerlayerdown", "speed": "10000", "address": "02:00:00:00:00:35"})
	return files
}

// `perch-collector ports` prints the array the gateway report carries,
// indented, with the default-route interface as role "wan".
func TestPortsCommand(t *testing.T) {
	root := writeTree(t, routerInAContainer())
	var stdout, stderr bytes.Buffer
	if code := portsCommand(nil, &stdout, &stderr, hoststat.FS{Root: root}); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	want := `[
  {
    "name": "wan0",
    "label": "wan0",
    "role": "wan",
    "medium": "virtual",
    "mac": "02:00:00:00:00:35",
    "adminUp": true,
    "carrier": false,
    "operstate": "lowerlayerdown",
    "speedMbps": 10000,
    "carrierChanges": 3
  },
  {
    "name": "lan0",
    "label": "lan0",
    "medium": "virtual",
    "mac": "02:00:00:00:00:29",
    "adminUp": true,
    "carrier": true,
    "operstate": "up",
    "speedMbps": 10000,
    "duplex": "full",
    "carrierChanges": 2
  }
]
`
	if stdout.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", stdout.String(), want)
	}
}

func TestPortsCommandEdges(t *testing.T) {
	// No ports: an empty array, exit 0.
	root := writeTree(t, map[string]string{"sys/class/net/lo/type": "772\n", "sys/class/net/lo/ifindex": "1\n"})
	var stdout, stderr bytes.Buffer
	if code := portsCommand(nil, &stdout, &stderr, hoststat.FS{Root: root}); code != 0 || stdout.String() != "[]\n" || stderr.Len() != 0 {
		t.Fatalf("no ports: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}

	// No /sys/class/net: could not look, which is not "no ports".
	stdout.Reset()
	stderr.Reset()
	if code := portsCommand(nil, &stdout, &stderr, hoststat.FS{Root: t.TempDir()}); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "cannot list /sys/class/net") {
		t.Fatalf("no sysfs: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}

	// It takes no arguments; -h is its usage.
	stdout.Reset()
	stderr.Reset()
	if code := portsCommand([]string{"--wan", "wan0"}, &stdout, &stderr, hoststat.FS{Root: root}); code != 2 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "usage: perch-collector ports") {
		t.Fatalf("argument: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := portsCommand([]string{"-h"}, &stdout, &stderr, hoststat.FS{Root: root}); code != 0 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), "usage: perch-collector ports") {
		t.Fatalf("-h: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// The subcommand must answer before the daemon does anything, so that it can
// run next to the live collector on the router. The binary is built and run
// with an environment that would make the daemon fail its configuration
// (a bad value and an unparsable collector.yaml), write its instance id and
// a flush file, listen on a port and dial a controller whose address is a
// listener here: `ports` has to exit 0 at once, print a JSON array and
// nothing else, write no file and make no connection. Then a subcommand
// after a flag must be refused instead of starting the daemon.
func TestPortsSubcommandExitsEarly(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the binary with")
	}
	bin := filepath.Join(t.TempDir(), "perch-collector")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// The controller the daemon would dial.
	controller, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	// A free port for the API the daemon would open.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiAddr := l.Addr().String()
	l.Close()

	work := t.TempDir()
	env := []string{
		"PERCH_COLLECTOR_SERVER_URL=http://" + controller.Addr().String(),
		"PERCH_COLLECTOR_TRANSPORT=websocket",
		"PERCH_COLLECTOR_API_KEY=0123456789abcdef0123456789abcdef",
		"PERCH_COLLECTOR_LISTEN=" + apiAddr,
		"PERCH_COLLECTOR_INTERFACE=perch-test-none0",
		"PERCH_COLLECTOR_GATEWAY_MACS=02:00:00:00:00:01",
		"PERCH_COLLECTOR_INSTANCE_ID_FILE=" + filepath.Join(work, "instance-id"),
		"PERCH_COLLECTOR_FLUSH_FILE=" + filepath.Join(work, "flush.json"),
		"PERCH_COLLECTOR_GATEWAY_STATS=on",
	}
	run := func(dir string, env []string, args ...string) (stdout, stderr string, elapsed time.Duration, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir, cmd.Env = dir, env
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		start := time.Now()
		err = cmd.Run()
		return o.String(), e.String(), time.Since(start), err
	}
	noConnection := func() {
		t.Helper()
		controller.(*net.TCPListener).SetDeadline(time.Now().Add(300 * time.Millisecond))
		if c, err := controller.Accept(); err == nil {
			c.Close()
			t.Fatal("the binary connected to the controller address")
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("accept: %v", err)
		}
	}

	t.Run("ports", func(t *testing.T) {
		broken := t.TempDir()
		if err := os.WriteFile(filepath.Join(broken, "collector.yaml"), []byte("interface: [unclosed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, elapsed, err := run(broken, append(env, "PERCH_COLLECTOR_SNAP_LEN=not-a-number"), "ports")
		if err != nil {
			t.Fatalf("exit: %v\nstderr: %s", err, stderr)
		}
		if stderr != "" {
			t.Fatalf("stderr: %s", stderr)
		}
		if elapsed > 5*time.Second {
			t.Errorf("took %v", elapsed)
		}
		var ports []map[string]any
		if err := json.Unmarshal([]byte(stdout), &ports); err != nil || ports == nil {
			t.Fatalf("stdout is not a JSON array (%v): %q", err, stdout)
		}
		for _, name := range []string{"instance-id", "flush.json"} {
			if _, err := os.Stat(filepath.Join(work, name)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s was written (%v)", name, err)
			}
		}
		noConnection()
	})

	t.Run("after a flag", func(t *testing.T) {
		_, stderr, _, err := run(t.TempDir(), env, "-listen", apiAddr, "ports")
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(stderr, `unexpected argument "ports"`) {
			t.Fatalf("exit %v, stderr: %s", err, stderr)
		}
		if strings.Contains(stderr, "capture") {
			t.Fatalf("got as far as capture: %s", stderr)
		}
		noConnection()
	})
}
