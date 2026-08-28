# Completion report saga

`Ticket Service` coordinates completion-report generation through Kafka and a
transactional outbox. `Report Service` performs generation and compensates
created files through `File Service` when a result can no longer be accepted.

## States

- `PENDING` — generation request is active.
- `COMPLETED` — the generated file was accepted by Ticket Service.
- `FAILED` — generation or compensation exhausted its retry limit.
- `COMPENSATING` — deletion of an unaccepted generated file is in progress.
- `COMPENSATED` — the unaccepted file was deleted.

Each generation attempt has a deadline. The coordinator republishes the
original immutable request snapshot after a failure or timeout, up to
`COMPLETION_SAGA_MAX_ATTEMPTS`. A late or duplicate generated result is not
attached to the work report; Ticket Service emits
`ticket.completion_report.compensation_requested.v1` in the same database
transaction. Report Service deletes that file and responds with either
`ticket.completion_report.compensated.v1` or
`ticket.completion_report.compensation_failed.v1`.

## Administrative recovery

Run from `Ticket_Service` with the normal database environment variables:

```text
go run ./tools/retry-completion -report-id <work-report-uuid>
```

For a failed generation this republishes the original request. If a file is
still attached to a failed compensation, the command retries compensation
first. Only `FAILED` and `COMPENSATED` sagas can be resumed.
