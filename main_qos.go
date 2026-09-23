package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/qos"
)

// qosInstalled reports whether the perch-qos package is on this router.
func qosInstalled(onOpenWrt bool) bool {
	if !onOpenWrt {
		return false
	}
	_, err := os.Stat(qos.ConfigPath)
	return err == nil
}

// buildQoS starts the shaper's daemon loop when qos resolves on; nil
// otherwise.
func buildQoS(ctx context.Context, cfg config.Config, onOpenWrt bool) (*qos.Engine, <-chan struct{}) {
	done := make(chan struct{})
	if !cfg.QoSEnabled(qosInstalled(onOpenWrt)) {
		close(done)
		return nil, done
	}
	e := qos.NewEngine(&qos.OS{}, true)
	log.Printf("qos: traffic shaping from %s (per-device and bucket caps on ifb-pdn / ifb-pup)", qos.ConfigPath)
	go func() {
		e.Run(ctx)
		close(done)
	}()
	return e, done
}

const qosUsage = `usage: perch-collector qos apply|sync|stop|status|probe|render [-full]

Runs the Perch traffic shaper once and exits (the daemon keeps it applied):

  apply    lift a stop and bring the kernel to /etc/config/perch-qos and the
           last device set (idempotent; the batch lands in /tmp/perch-qos/)
  sync     like apply, but a stop stays in force (hotplug, reloads)
  stop     remove every Perch tc object and keep shaping off until apply
           (sqm on the WAN is not touched)
  status   the shaper's live state as JSON (what the controller receives)
  probe    what this router can do (kernel features, sqm, conflicts) as JSON
  render   print the tc batch apply would run now; -full: the whole tree
`

// qosCommand runs `perch-collector qos …`.
func qosCommand(args []string, stdout, stderr io.Writer, sys qos.System) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, qosUsage)
		return 2
	}
	e := qos.NewEngine(sys, false)
	e.LoadDevices()
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	report := func(r qos.ApplyResult) int {
		_ = enc.Encode(r)
		if len(r.Errors) > 0 {
			return 1
		}
		return 0
	}
	switch args[0] {
	case "apply", "start", "reload":
		return report(e.Start("cli " + args[0]))
	case "stop":
		return report(e.Stop())
	case "sync":
		return report(e.Reconcile("cli sync", true))
	case "status":
		e.Plan()
		_ = enc.Encode(e.StatusReport())
		return 0
	case "probe":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = enc.Encode(e.Probe(ctx))
		return 0
	case "render":
		full := len(args) > 1 && args[1] == "-full"
		text, err := e.Render(full)
		if err != nil {
			fmt.Fprintf(stderr, "perch-collector qos render: %v\n", err)
			return 1
		}
		fmt.Fprint(stdout, text)
		return 0
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, qosUsage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown qos command %q\n\n%s", args[0], qosUsage)
	return 2
}
