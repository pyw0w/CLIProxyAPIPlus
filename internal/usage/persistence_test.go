package usage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	coreusage "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/usage"
)

func TestStatisticsPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "usage-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "stats.json")
	stats := NewRequestStatistics()

	// 1. Record some data
	ctx := context.Background()
	record := coreusage.Record{
		RequestedAt: time.Now(),
		APIKey:      "test-key",
		Model:       "gpt-4",
		Detail: coreusage.Detail{
			InputTokens:  10,
			OutputTokens: 20,
		},
	}
	stats.Record(ctx, record)

	if stats.totalRequests != 1 {
		t.Errorf("expected 1 request, got %d", stats.totalRequests)
	}

	// 2. Save to file
	if err := stats.SaveToFile(path); err != nil {
		t.Fatalf("failed to save to file: %v", err)
	}

	// 3. Load into new statistics object
	newStats := NewRequestStatistics()
	if err := newStats.LoadFromFile(path); err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}

	if newStats.totalRequests != 1 {
		t.Errorf("expected 1 request in loaded stats, got %d", newStats.totalRequests)
	}

    snapshot := newStats.Snapshot()
    if snapshot.TotalTokens != 30 {
        t.Errorf("expected 30 total tokens, got %d", snapshot.TotalTokens)
    }

	// 4. Record more and merge
	record2 := coreusage.Record{
		RequestedAt: time.Now().Add(time.Second),
		APIKey:      "test-key",
		Model:       "gpt-4",
		Detail: coreusage.Detail{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	stats.Record(ctx, record2)

	if err := stats.SaveToFile(path); err != nil {
		t.Fatalf("failed to save updated stats: %v", err)
	}

	finalStats := NewRequestStatistics()
	if err := finalStats.LoadFromFile(path); err != nil {
		t.Fatalf("failed to load updated stats: %v", err)
	}

	if finalStats.totalRequests != 2 {
		t.Errorf("expected 2 requests in final stats, got %d", finalStats.totalRequests)
	}
}
