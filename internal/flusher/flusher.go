package flusher

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/capthndsme/perch-collector/internal/aggregator"
)

// Flusher periodically writes aggregator snapshots to a JSON file on disk.
type Flusher struct {
	agg      *aggregator.Aggregator
	filePath string
	interval time.Duration
	done     chan struct{}
}

// flushPayload is the JSON shape written to disk.
type flushPayload struct {
	FlushedAt string                   `json:"flushed_at"`
	Devices   []aggregator.DeviceStats `json:"devices"`
	Summary   aggregator.Summary       `json:"summary"`
}

// New creates a new Flusher.
func New(agg *aggregator.Aggregator, filePath string, intervalSecs int) *Flusher {
	return &Flusher{
		agg:      agg,
		filePath: filePath,
		interval: time.Duration(intervalSecs) * time.Second,
		done:     make(chan struct{}),
	}
}

// Run starts the periodic flush loop. It blocks until Stop() is called.
func (f *Flusher) Run() {
	log.Printf("flusher: writing to %s every %s", f.filePath, f.interval)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-f.done:
			// Final flush before exit.
			if err := f.flush(); err != nil {
				log.Printf("flusher: final flush error: %v", err)
			} else {
				log.Println("flusher: final flush complete")
			}
			return
		case <-ticker.C:
			if err := f.flush(); err != nil {
				log.Printf("flusher: error: %v", err)
			}
		}
	}
}

// flush writes the current aggregator state to the JSON file.
func (f *Flusher) flush() error {
	devices := f.agg.Snapshot(time.Time{})
	summary := f.agg.GetSummary()

	payload := flushPayload{
		FlushedAt: time.Now().UTC().Format(time.RFC3339),
		Devices:   devices,
		Summary:   summary,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	// Ensure the directory exists.
	dir := filepath.Dir(f.filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating directory %q: %w", dir, err)
	}

	// Write atomically: write to temp file, then rename.
	tmpPath := f.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0640); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, f.filePath); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

// Stop signals the flush loop to exit (with a final flush).
func (f *Flusher) Stop() {
	select {
	case <-f.done:
		return
	default:
		close(f.done)
	}
}
