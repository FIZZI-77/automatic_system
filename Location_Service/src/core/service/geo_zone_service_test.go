package service

import (
	"context"
	"errors"
	"testing"

	"location/models"
	"location/src/core/repository"

	"github.com/google/uuid"
)

type geoZoneRepoStub struct {
	created *models.GeoZone
	err     error
}

func (s *geoZoneRepoStub) CreateGeoZone(
	context.Context,
	*models.CreateGeoZoneInput,
) (*models.CreateGeoZoneResult, error) {
	return &models.CreateGeoZoneResult{Zone: s.created}, s.err
}

func (s *geoZoneRepoStub) UpdateGeoZone(
	context.Context,
	*models.UpdateGeoZoneInput,
) (*models.UpdateGeoZoneResult, error) {
	return &models.UpdateGeoZoneResult{Zone: s.created}, s.err
}

func (s *geoZoneRepoStub) DeleteGeoZone(
	context.Context,
	*models.DeleteGeoZoneInput,
) (*models.DeleteGeoZoneResult, error) {
	return &models.DeleteGeoZoneResult{Zone: s.created}, s.err
}

func (s *geoZoneRepoStub) ListGeoZones(
	context.Context,
	*models.ListGeoZonesInput,
) (*models.ListGeoZonesResult, error) {
	return &models.ListGeoZonesResult{Zones: []*models.GeoZone{s.created}, Total: 1}, s.err
}

func (s *geoZoneRepoStub) CheckPointInZones(
	context.Context,
	*models.CheckPointInZonesInput,
) (*models.CheckPointInZonesResult, error) {
	return &models.CheckPointInZonesResult{Zones: []*models.GeoZone{s.created}}, s.err
}

func TestGeoZoneServiceAuthorization(t *testing.T) {
	zone := &models.GeoZone{ID: uuid.New(), DepartmentID: uuid.New(), Name: "zone", Active: true}
	repo := repository.NewRepository(nil, nil, &geoZoneRepoStub{created: zone})
	svc := NewGeoZoneServiceStruct(repo)
	input := &models.CreateGeoZoneInput{
		DepartmentID: zone.DepartmentID,
		Name:         zone.Name,
		GeoJSON:      "{}",
		ActorRoles:   []string{"viewer"},
	}
	if _, err := svc.CreateGeoZone(context.Background(), input); !errors.Is(
		err,
		models.ErrPermissionDenied,
	) {
		t.Fatalf("permission error = %v", err)
	}
	input.ActorRoles = []string{" Dispatcher "}
	result, err := svc.CreateGeoZone(context.Background(), input)
	if err != nil {
		t.Fatalf("create zone: %v", err)
	}
	if result.Zone.ID != zone.ID {
		t.Fatalf("zone id = %s", result.Zone.ID)
	}
}

func TestGeoZoneServiceValidationPrecedesAuthorization(t *testing.T) {
	repo := repository.NewRepository(nil, nil, &geoZoneRepoStub{})
	_, err := NewGeoZoneServiceStruct(
		repo,
	).CreateGeoZone(context.Background(), &models.CreateGeoZoneInput{ActorRoles: []string{"admin"}})
	if !errors.Is(err, models.ErrValidation) {
		t.Fatalf("error = %v", err)
	}
}

func TestCanManageZones(t *testing.T) {
	for _, role := range []string{"admin", "SYSTEM_ADMIN", " dispatcher "} {
		if !canManageZones([]string{role}) {
			t.Fatalf("role %q denied", role)
		}
	}
	if canManageZones([]string{"viewer", "driver"}) {
		t.Fatal("unauthorized roles accepted")
	}
}
