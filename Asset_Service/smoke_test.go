package asset_test

import (
	"context"
	"os"
	"testing"
	"time"

	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSmoke(t *testing.T) {
	if os.Getenv("ASSET_SMOKE") == "" {
		t.Skip("set ASSET_SMOKE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := grpc.NewClient("localhost:50065", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := assetv1.NewAssetServiceClient(conn)
	actor, department := uuid.NewString(), uuid.NewString()
	created, err := c.CreateAsset(ctx, &assetv1.CreateAssetRequest{ActorUserId: actor, ActorRoles: []string{"admin"}, DepartmentId: department, Type: "street_light", Name: "Smoke light", Address: "Moscow", District: "Yasenevo", GeometryGeoJson: `{"type":"Point","coordinates":[37.53,55.61]}`, InstallationYear: ptr(int32(2010)), ServiceLifeYears: ptr(int32(20)), InspectionIntervalDays: 180, Criticality: .9})
	if err != nil {
		t.Fatal(err)
	}
	id := created.Asset.Id
	name := "Updated smoke light"
	if _, err = c.UpdateAsset(ctx, &assetv1.UpdateAssetRequest{AssetId: id, ActorUserId: actor, ActorRoles: []string{"admin"}, Name: &name}); err != nil {
		t.Fatal(err)
	}
	near, err := c.FindNearbyAssets(ctx, &assetv1.FindNearbyAssetsRequest{Latitude: 55.61, Longitude: 37.53, RadiusMeters: 100, Limit: 10})
	if err != nil || len(near.Assets) == 0 {
		t.Fatalf("nearby: %v, count=%d", err, len(near.Assets))
	}
	for i := 0; i < 2; i++ {
		incident, e := c.RecordIncident(ctx, &assetv1.RecordIncidentRequest{AssetId: id, FailureType: "lamp_failure", Description: "off", Source: "smoke", Priority: "HIGH", OccurredAt: timestamppb.Now(), ActorUserId: actor, ActorRoles: []string{"worker"}})
		if e != nil {
			t.Fatal(e)
		}
		if i == 1 && !incident.Incident.Repeated {
			t.Fatal("second incident was not marked repeated")
		}
	}
	prediction, err := c.GetFailurePrediction(ctx, &assetv1.GetFailurePredictionRequest{AssetId: id})
	if err != nil || prediction.Prediction.RiskScore <= 0 {
		t.Fatalf("prediction: %v %#v", err, prediction.Prediction)
	}
	if _, err = c.CompleteRepair(ctx, &assetv1.CompleteRepairRequest{AssetId: id, Description: "lamp replaced", DurationMinutes: 30, CompletedAt: timestamppb.Now(), ActorUserId: actor, ActorRoles: []string{"worker"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.RecordInspection(ctx, &assetv1.RecordInspectionRequest{AssetId: id, InspectorUserId: actor, Kind: "scheduled", Result: "ok", ConditionScore: .8, InspectedAt: timestamppb.Now(), ActorRoles: []string{"worker"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.CreateMaintenancePlan(ctx, &assetv1.CreateMaintenancePlanRequest{AssetId: id, Kind: "inspection", IntervalDays: 180, NextDueAt: timestamppb.New(time.Now().Add(time.Hour)), ActorUserId: actor, ActorRoles: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	due, err := c.ListDueMaintenance(ctx, &assetv1.ListDueMaintenanceRequest{DueBefore: timestamppb.New(time.Now().Add(2 * time.Hour)), Limit: 10})
	if err != nil || len(due.Plans) == 0 {
		t.Fatalf("due plans: %v, count=%d", err, len(due.Plans))
	}
	t.Logf("asset=%s risk=%.1f level=%s due=%d", id, prediction.Prediction.RiskScore, prediction.Prediction.RiskLevel, len(due.Plans))
}

func ptr[T any](v T) *T { return &v }
