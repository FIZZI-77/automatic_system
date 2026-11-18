package service

import (
	"math"
	"sort"

	"dispatch/models"

	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	"github.com/google/uuid"
)

// distanceCandidates ранжирует подходящие бригады по расстоянию по прямой,
// когда Routing недоступен. ETASeconds=-1 означает неизвестное время прибытия;
// Reachable разрешает попытку автоназначения, но не подтверждает наличие дорожного маршрута.
func distanceCandidates(candidates []*routingv1.Candidate, latitude, longitude float64, limit int32) []models.Candidate {
	result := make([]models.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		id, err := uuid.Parse(candidate.GetBrigadeId())
		point := candidate.GetLocation()
		if err != nil || point == nil {
			continue
		}
		result = append(result, models.Candidate{
			BrigadeID: id, Latitude: point.GetLatitude(), Longitude: point.GetLongitude(),
			DistanceMeters: straightLineDistance(point.GetLatitude(), point.GetLongitude(), latitude, longitude),
			ETASeconds:     -1, Reachable: true,
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].DistanceMeters == result[j].DistanceMeters {
			return result[i].BrigadeID.String() < result[j].BrigadeID.String()
		}
		return result[i].DistanceMeters < result[j].DistanceMeters
	})
	if limit > 0 && int(limit) < len(result) {
		result = result[:limit]
	}
	for i := range result {
		result[i].Rank = int32(i + 1)
	}
	return result
}

// straightLineDistance возвращает расстояние в метрах по дуге большого круга;
// координаты передаются в градусах, дорожная сеть не учитывается.
func straightLineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const radians = math.Pi / 180
	dlat, dlon := (lat2-lat1)*radians, (lon2-lon1)*radians
	a := math.Pow(math.Sin(dlat/2), 2) + math.Cos(lat1*radians)*math.Cos(lat2*radians)*math.Pow(math.Sin(dlon/2), 2)
	return 6371000 * 2 * math.Asin(math.Sqrt(min(1, max(0, a))))
}
