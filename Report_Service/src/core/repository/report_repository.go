package repository

import (
	"context"
	"encoding/json"
	"report/models"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ReportRepoStruct struct{ db *pgxpool.Pool }

// NewReportRepoStruct создаёт хранилище заданий отчётов с пулом db.
func NewReportRepoStruct(db *pgxpool.Pool) *ReportRepoStruct { return &ReportRepoStruct{db: db} }

const columns = `id,requested_by,name,type,format,status,filter,actor_roles,file_id,error,attempts,created_at,updated_at,completed_at`
const qualifiedColumns = `reports.id,reports.requested_by,reports.name,reports.type,reports.format,reports.status,reports.filter,reports.actor_roles,reports.file_id,reports.error,reports.attempts,reports.created_at,reports.updated_at,reports.completed_at`

// scan читает отчёт и декодирует JSON-фильтр. Ошибку Scan возвращает с nil,
// ошибку декодирования — вместе с уже прочитанной моделью.
func scan(row pgx.Row) (*models.Report, error) {
	var r models.Report
	var raw []byte
	e := row.Scan(&r.ID, &r.RequestedBy, &r.Name, &r.Type, &r.Format, &r.Status, &raw, &r.ActorRoles, &r.FileID, &r.Error, &r.Attempts, &r.CreatedAt, &r.UpdatedAt, &r.CompletedAt)

	if e != nil {
		return nil, e
	}

	e = json.Unmarshal(raw, &r.Filter)
	return &r, e
}

// Create транзакционно сохраняет задание отчёта с параметрами и ролями инициатора
// вместе с событием report.CREATED. Начальный статус и временные метки задаёт база.
func (r *ReportRepoStruct) Create(c context.Context, v models.CreateInput) (*models.Report, error) {
	raw, _ := json.Marshal(v.Filter)
	tx, e := r.db.Begin(c)

	if e != nil {
		return nil, e
	}

	defer tx.Rollback(c)
	item, e := scan(tx.QueryRow(c, `INSERT INTO reports(requested_by,name,type,format,filter,actor_roles) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+columns, v.RequestedBy, v.Name, v.Type, v.Format, raw, v.ActorRoles))

	if e != nil {
		return nil, e
	}

	e = event(c, tx, item, "report.CREATED")

	if e == nil {
		e = tx.Commit(c)
	}

	return item, e
}

// Get возвращает задание отчёта по ID; отсутствие даёт pgx.ErrNoRows.
func (r *ReportRepoStruct) Get(c context.Context, id uuid.UUID) (*models.Report, error) {
	return scan(r.db.QueryRow(c, `SELECT `+columns+` FROM reports WHERE id=$1`, id))
}

// List возвращает страницу заданий по инициатору и статусу от новых к старым
// с отдельным общим счётчиком. Пагинацию f не проверяет и не нормализует.
func (r *ReportRepoStruct) List(c context.Context, f models.ListFilter) ([]*models.Report, int64, error) {
	where := []string{"TRUE"}
	args := []any{}

	if f.RequestedBy != nil {
		args = append(args, *f.RequestedBy)
		where = append(where, `requested_by=$`+itoa(len(args)))
	}

	if f.Status != nil {
		args = append(args, *f.Status)
		where = append(where, `status=$`+itoa(len(args)))
	}

	w := strings.Join(where, " AND ")
	var total int64

	if e := r.db.QueryRow(c, `SELECT count(*) FROM reports WHERE `+w, args...).Scan(&total); e != nil {
		return nil, 0, e
	}

	args = append(args, f.Limit, f.Offset)
	rows, e := r.db.Query(c, `SELECT `+columns+` FROM reports WHERE `+w+` ORDER BY created_at DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)

	if e != nil {
		return nil, 0, e
	}

	defer rows.Close()
	out := []*models.Report{}
	for rows.Next() {
		x, e := scan(rows)

		if e != nil {
			return nil, 0, e
		}

		out = append(out, x)
	}
	return out, total, rows.Err()
}

// Cancel переводит PENDING или FAILED в CANCELED с очисткой ошибки и событием outbox.
// Отсутствие задания или другой исходный статус возвращает как pgx.ErrNoRows.
func (r *ReportRepoStruct) Cancel(c context.Context, id uuid.UUID) (*models.Report, error) {
	return r.transition(c, id, `status IN('PENDING','FAILED')`, models.StatusCanceled, "report.CANCELED")
}

// Retry переводит FAILED в PENDING с очисткой ошибки и событием report.RETRIED.
// Счётчик попыток сохраняет; отсутствие задания или другой статус даёт pgx.ErrNoRows.
func (r *ReportRepoStruct) Retry(c context.Context, id uuid.UUID) (*models.Report, error) {
	return r.transition(c, id, `status='FAILED'`, models.StatusPending, "report.RETRIED")
}

// transition транзакционно меняет статус при SQL-условии condition, очищает ошибку
// и записывает событие kind. condition задаётся внутренним кодом;
// отсутствие подходящей строки возвращает как pgx.ErrNoRows.
func (r *ReportRepoStruct) transition(c context.Context, id uuid.UUID, condition string, status models.Status, kind string) (*models.Report, error) {
	tx, e := r.db.Begin(c)

	if e != nil {
		return nil, e
	}

	defer tx.Rollback(c)
	x, e := scan(tx.QueryRow(c, `UPDATE reports SET status=$2,error=NULL,updated_at=now() WHERE id=$1 AND `+condition+` RETURNING `+columns, id, status))

	if e != nil {
		return nil, e
	}

	if e = event(c, tx, x, kind); e == nil {
		e = tx.Commit(c)
	}

	return x, e
}

// Claim транзакционно захватывает старейшее PENDING-задание либо PROCESSING,
// не обновлявшееся пять минут, пропуская заблокированные строки. Возвращает задание
// в PROCESSING с увеличенным Attempts; отсутствие работы даёт pgx.ErrNoRows.
func (r *ReportRepoStruct) Claim(c context.Context) (*models.Report, error) {
	tx, e := r.db.Begin(c)

	if e != nil {
		return nil, e
	}

	defer tx.Rollback(c)
	x, e := scan(tx.QueryRow(c, `WITH next AS (SELECT id FROM reports WHERE status='PENDING' OR status='PROCESSING' AND updated_at < now()-interval '5 minutes' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE reports SET status='PROCESSING',attempts=reports.attempts+1,updated_at=now() FROM next WHERE reports.id=next.id RETURNING `+qualifiedColumns))

	if e == nil {
		e = tx.Commit(c)
	}

	return x, e
}

// Complete отмечает PROCESSING-задание COMPLETED для актуальной попытки attempt,
// сохраняя file, время завершения и событие outbox в одной транзакции.
// Несовпадение статуса или попытки возвращает как pgx.ErrNoRows.
func (r *ReportRepoStruct) Complete(c context.Context, id, file uuid.UUID, attempt int32) error {
	tx, e := r.db.Begin(c)

	if e != nil {
		return e
	}

	defer tx.Rollback(c)
	x, e := scan(tx.QueryRow(c, `UPDATE reports SET status='COMPLETED',file_id=$2,error=NULL,completed_at=now(),updated_at=now() WHERE id=$1 AND status='PROCESSING' AND attempts=$3 RETURNING `+columns, id, file, attempt))

	if e == nil {
		e = event(c, tx, x, "report.COMPLETED")
	}

	if e == nil {
		e = tx.Commit(c)
	}

	return e
}

// Fail отмечает PROCESSING-задание FAILED с причиной msg и событием outbox
// в одной транзакции. Несовпадение статуса или попытки attempt даёт pgx.ErrNoRows.
func (r *ReportRepoStruct) Fail(c context.Context, id uuid.UUID, attempt int32, msg string) error {
	tx, e := r.db.Begin(c)

	if e != nil {
		return e
	}

	defer tx.Rollback(c)
	x, e := scan(tx.QueryRow(c, `UPDATE reports SET status='FAILED',error=$3,updated_at=now() WHERE id=$1 AND status='PROCESSING' AND attempts=$2 RETURNING `+columns, id, attempt, msg))

	if e == nil {
		e = event(c, tx, x, "report.FAILED")
	}

	if e == nil {
		e = tx.Commit(c)
	}

	return e
}

// event сохраняет событие отчёта в outbox через tx, используя время r.UpdatedAt
// и новый UUID внутри полезной нагрузки.
func event(c context.Context, tx pgx.Tx, r *models.Report, kind string) error {
	payload, _ := json.Marshal(map[string]any{
		"event_id":     uuid.New(),
		"event_type":   kind,
		"occurred_at":  r.UpdatedAt,
		"aggregate_id": r.ID,
		"report_id":    r.ID,
		"requested_by": r.RequestedBy,
		"status":       r.Status,
		"file_id":      r.FileID,
	})
	_, e := tx.Exec(c, `INSERT INTO outbox_events(aggregate_id,event_type,payload) VALUES($1,$2,$3)`, r.ID, kind, payload)
	return e
}

// itoa возвращает десятичную цифру для n от 0 до 9 и пустую строку для n >= 10.
// Отрицательное n вызывает панику; используется для номеров SQL-параметров.
func itoa(n int) string {
	const d = "0123456789"

	if n < 10 {
		return string(d[n])
	}

	return ""
}
