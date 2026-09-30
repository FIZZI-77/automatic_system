package models

type DepartmentPerformance struct {
	DepartmentID                         string
	Created                              uint64
	Completed                            uint64
	Canceled                             uint64
	Active                               uint64
	CompletionRate                       float64
	AverageResponseSeconds               float64
	AverageResolutionSeconds             float64
	ResponseSampleCount                  uint64
	ResolutionSampleCount                uint64
	ResponseSLASampleCount               uint64
	ResponseSLABreaches                  uint64
	AverageResponseSLADeviationSeconds   float64
	ResolutionSLASampleCount             uint64
	ResolutionSLABreaches                uint64
	AverageResolutionSLADeviationSeconds float64
	FeedbackCount                        uint64
	AverageRating                        float64
	PositiveRatingRate                   float64
	ResolvedFeedbackRate                 float64
	FeedbackResponseRate                 float64
}

type DepartmentPerformanceReport struct {
	Departments  []DepartmentPerformance
	Organization DepartmentPerformance
}
