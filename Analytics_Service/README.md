# Analytics Service

Kafka-driven ClickHouse read model for ticket volume, lifecycle time, SLA breaches and breakdowns. The service is read-only from the business workflow perspective and supports replay through a new Kafka consumer group.

`GetOperationalLatency` reports separate assignment and route-calculation distributions. Each distribution includes sample count, average, median, p90, p95 and p99. Assignment time starts at `dispatch.requested` when that event exists and falls back to `ticket.created`; route-calculation time uses the measured engine-call duration and never the route ETA.

Operational filters support time range, department, category, priority, brigade, assignment mode, failure code and success. Event payload extraction is case- and naming-style-insensitive and searches nested envelopes, so `calculation_duration_ms`, `CalculationDurationMs` and nested `data` payloads project consistently.

`GetOperationalLatencyRequest.group_by` optionally returns comparison groups. Assignment latency supports department, category, priority, assignment mode and brigade; routing latency additionally supports engine, travel mode, success and failure code. The ungrouped distributions remain present for backward compatibility.

The Dispatch failure read model groups the `dispatch.events.v1` lifecycle by
`operation_id`, not by ticket, so retries are measured independently. Its
denominator is the number of operations that contain `dispatch.requested`;
the failure rate is `(FAILED + EXPIRED + CANCELED) / requested * 100`.
Breakdown percentages use all unsuccessful terminal operations as their
denominator. Unknown event versions and empty stage/code values are excluded
from projections and named breakdowns respectively. The repository/service
port and public gRPC/Gateway APIs are implemented.

The same response classifies assignment failures into three mutually exclusive
business reasons: `NO_SUITABLE_BRIGADE` for an explicit empty reachable-candidate
result, `NO_ROUTE` for a failed operation at the routing stage, and
`RESERVATION_EXPIRED` for an expired operation or matching failure code. Each
reason reports its share of all requested operations. Department and category
breakdowns return the top 10 values per reason and their share inside that
reason; unclassified technical failures remain available in the raw stage/code
breakdowns.

The brigade workload read model reconstructs the latest ticket state as of the
filter end time. `active` is the number of tickets whose latest status is
`ASSIGNED` or `IN_PROGRESS`; `unassigned_backlog` is the number whose latest
status is `NEW` and has no brigade. Incoming, assigned and completed counters
count their corresponding events inside the requested period and are returned
both as totals and per brigade. Balance uses the population standard deviation,
`coefficient_of_variation = standard_deviation / average_active`, and the
standard Gini coefficient over current active-ticket counts, including idle
operational brigades.

The active-worker read model uses the latest Brigade member event for every
`member_id`. An active member has `active=true` and is not `REMOVED`; an
available member additionally has `availability_status=AVAILABLE`. Totals are
grouped by department and brigade. `on_shift` counts active members whose
brigade has a `BrigadeShiftStarted` event without a matching
`BrigadeShiftEnded` event at the requested snapshot time.

Brigade status transitions provide factual shift lifecycle events. The first
transition to `AVAILABLE` opens one shift; repeated `BUSY/ON_ROUTE -> AVAILABLE`
transitions do not open another one. `OFFLINE`, `INACTIVE`, or `ARCHIVED` closes
the active shift. `GetBrigadePerformance` reports:

- `completed_per_shift = completed tickets / factual shift count`;
- `busy_hours = sum of valid execution durations / 3600`;
- `shift_hours = sum(shift end or filter end - shift start) / 3600`;
- `average_parallel_tasks = busy_hours / shift_hours`;
- `utilization_rate = min(100, average_parallel_tasks * 100)`.

Execution starts at `IN_PROGRESS`, with assignment time as a fallback, and ends
at completion. SLA breach rate uses completed tickets as the denominator.
Repeated asset tickets are completed tickets after the first ticket for the
same non-empty `asset_id` in the selected cohort.

The assignment funnel uses Dispatch operations requested inside the selected
period as its cohort. `candidates found` requires a positive `candidate_count`;
later stages require their corresponding lifecycle event. Every stage reports
conversion from the previous stage and the transition-time distribution with
sample count, average, median, p90, p95 and p99. Operations without
`dispatch.requested` in the period cannot inflate later-stage conversion.

`GetDispatchEffectiveness` compares `AUTOMATIC` and `MANUAL` operations by
requested count, assigned count, success rate and assignment-time distribution.
The response explicitly reports `manual_reassignment_available=false`: the
Ticket domain currently has no reassignment transition or `ticket.reassigned`
event, so returning a synthetic zero would be misleading.

Operational insights use the following definitions. Departure time is the
interval from assignment to the earliest `IN_PROGRESS` transition or accepted
vehicle position with speed at least 5 km/h and accuracy at most 50 metres.
ETA error is actual geofence arrival minus the latest route prediction; the API
returns bias, mean and p95 absolute error, sample count, and the share within
five minutes. Queue age uses active unassigned `NEW` tickets at the filter end.
Capacity forecasting is deliberately transparent:
`ceil(peak_hourly_incoming * average_resolution_seconds / 3600)`.

Projection health reports source-event freshness, event-to-ClickHouse p95,
projection eligibility, and unknown event versions. Kafka consumer operation,
error, processing-duration and bounded-topic lag metrics are exported to
Prometheus. `tools/replay` rebuilds a new versioned table from the immutable raw
event table, reconciles unique counts, atomically exchanges tables, and catches
events that arrived during the exchange.

Kafka processing is offset-safe. A fetched message is processed synchronously
up to five times with bounded exponential backoff, so a later offset cannot
accidentally commit an earlier failed event. Invalid JSON and events that still
fail after the retry budget are copied byte-for-byte to `<source-topic>.dlq`
with source partition/offset, attempt count and error headers. The source offset
is committed only after the ClickHouse write or the DLQ publish succeeds; a DLQ
write failure stops that worker instead of losing the event.

Local development uses one ClickHouse node. Production should use ClickHouse Keeper, replicated local tables and Distributed query tables across at least two shards with two replicas when availability and measured load require it.
