package handlers

import (
	"testing"

	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
)

func TestDispatchStatus(t *testing.T) {
	tests := map[string]dispatchv1.DispatchStatus{"PENDING": dispatchv1.DispatchStatus_DISPATCH_STATUS_PENDING, "reserved": dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED, "CONFIRMING": dispatchv1.DispatchStatus_DISPATCH_STATUS_CONFIRMING, "ASSIGNED": dispatchv1.DispatchStatus_DISPATCH_STATUS_ASSIGNED, "FAILED": dispatchv1.DispatchStatus_DISPATCH_STATUS_FAILED, "CANCELLED": dispatchv1.DispatchStatus_DISPATCH_STATUS_CANCELLED, "EXPIRED": dispatchv1.DispatchStatus_DISPATCH_STATUS_EXPIRED}
	for input, expected := range tests {
		if actual := dispatchStatus(input); actual != expected {
			t.Fatalf("%s: got %v, want %v", input, actual, expected)
		}
	}
	if dispatchStatus("bad") != dispatchv1.DispatchStatus_DISPATCH_STATUS_UNSPECIFIED {
		t.Fatal("unknown status must remain unspecified")
	}
}
