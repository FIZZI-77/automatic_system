package handlers

import (
	"testing"

	"gateway/models"

	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
)

func TestRoutingEnums(t *testing.T) {
	if routingMode("truck") != routingv1.TravelMode_TRAVEL_MODE_TRUCK {
		t.Fatal("truck mode mapping failed")
	}
	if routingMode("unknown") != routingv1.TravelMode_TRAVEL_MODE_AUTO {
		t.Fatal("default mode must be auto")
	}
	if routingStatus("ACTIVE") != routingv1.RouteStatus_ROUTE_STATUS_ACTIVE {
		t.Fatal("active status mapping failed")
	}
}

func TestRoutingOptionsMapsVehicle(t *testing.T) {
	height := 3.2
	result := routingOptions(models.RoutingOptions{TravelMode: "truck", Vehicle: &models.RoutingVehicleConstraints{HeightMeters: &height}})
	if result.GetTravelMode() != routingv1.TravelMode_TRAVEL_MODE_TRUCK || result.GetVehicle().GetHeightMeters() != height {
		t.Fatalf("unexpected options: %+v", result)
	}
}
