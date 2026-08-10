package handlers

import (
	"testing"
	"time"

	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLocationEnumMappers(t *testing.T) {
	if toProtoSubjectType("brigade") != locationv1.SubjectType_SUBJECT_TYPE_BRIGADE {
		t.Fatal("brigade subject mapping")
	}
	if toProtoSubjectType("vehicle") != locationv1.SubjectType_SUBJECT_TYPE_VEHICLE {
		t.Fatal("vehicle subject mapping")
	}
	if toProtoSubjectType("device") != locationv1.SubjectType_SUBJECT_TYPE_DEVICE {
		t.Fatal("device subject mapping")
	}
	if toProtoSubjectType("bad") != locationv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED {
		t.Fatal("invalid subject mapping")
	}
	if toProtoLocationSortOrder("ASC") != locationv1.SortOrder_SORT_ORDER_ASC {
		t.Fatal("ascending order mapping")
	}
	if toProtoLocationSortOrder("desc") != locationv1.SortOrder_SORT_ORDER_DESC {
		t.Fatal("descending order mapping")
	}
	if fromProtoSignalStatus(locationv1.SignalStatus_SIGNAL_STATUS_OFFLINE) != "OFFLINE" {
		t.Fatal("signal mapping")
	}
}

func TestFromProtoCurrentLocation(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	altitude := 150.5
	value := &locationv1.CurrentLocation{SignalStatus: locationv1.SignalStatus_SIGNAL_STATUS_ONLINE, StaleAfter: timestamppb.New(now.Add(time.Minute)), Position: &locationv1.Position{Id: "position", EventId: "event", BrigadeId: "brigade", Latitude: 55.75, Longitude: 37.61, AltitudeMeters: &altitude, RecordedAt: timestamppb.New(now), ReceivedAt: timestamppb.New(now)}}
	result := fromProtoCurrentLocation(value)
	if result == nil || result.Position == nil {
		t.Fatal("location is nil")
	}
	if result.Position.AltitudeMeters == nil || *result.Position.AltitudeMeters != altitude {
		t.Fatalf("altitude = %v", result.Position.AltitudeMeters)
	}
	if result.SignalStatus != "ONLINE" || result.StaleAfter != now.Add(time.Minute).Unix() {
		t.Fatalf("result = %#v", result)
	}
}
