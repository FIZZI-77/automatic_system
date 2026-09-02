package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteMarkdownUsesNAForUnmeasuredCapacity(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := WriteMarkdown(&output, Summary{Scenario: "ticket-write"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "N/A") {
		t.Fatalf("report = %q, want N/A", output.String())
	}
}
