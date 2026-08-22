package generator

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"github.com/jung-kurt/gofpdf"
	"github.com/xuri/excelize/v2"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"report/models"
	"strings"
)

type Generator struct{}

func New() *Generator { return &Generator{} }
func (g *Generator) Generate(format models.Format, name string, rows [][]string) (models.Artifact, error) {
	switch format {
	case models.FormatCSV:
		return csvFile(name, rows)
	case models.FormatXLSX:
		return xlsxFile(name, rows)
	case models.FormatPDF:
		return pdfFile(name, rows)
	default:
		return models.Artifact{}, fmt.Errorf("unsupported format %s", format)
	}
}
func safe(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "report"
	}
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' {
			return '-'
		}
		return r
	}, v)
}
func csvFile(name string, rows [][]string) (models.Artifact, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	e := w.WriteAll(rows)
	if e == nil {
		e = w.Error()
	}
	return models.Artifact{Name: safe(name) + ".csv", ContentType: "text/csv", Data: b.Bytes()}, e
}
func xlsxFile(name string, rows [][]string) (models.Artifact, error) {
	f := excelize.NewFile()
	defer f.Close()
	for i, row := range rows {
		for j, v := range row {
			cell, _ := excelize.CoordinatesToCellName(j+1, i+1)
			_ = f.SetCellValue("Sheet1", cell, v)
		}
	}
	b, e := f.WriteToBuffer()
	if e != nil {
		return models.Artifact{}, e
	}
	return models.Artifact{Name: safe(name) + ".xlsx", ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Data: b.Bytes()}, nil
}
func pdfFile(name string, rows [][]string) (models.Artifact, error) {
	p := gofpdf.New("L", "mm", "A4", "")
	p.AddPage()
	p.SetFont("Arial", "B", 14)
	p.Cell(0, 10, name)
	p.Ln(12)
	p.SetFont("Arial", "", 8)
	for _, row := range rows {
		width := 270.0 / float64(max(1, len(row)))
		for _, v := range row {
			p.CellFormat(width, 7, v, "1", 0, "L", false, 0, "")
		}
		p.Ln(7)
	}
	var b bytes.Buffer
	e := p.Output(&b)
	return models.Artifact{Name: safe(name) + ".pdf", ContentType: "application/pdf", Data: b.Bytes()}, e
}

// GenerateCompletion creates the concise work-completion act used by Ticket
// Service. It deliberately contains only the fields required by the business
// flow and embeds supported photos on following pages.
func (g *Generator) GenerateCompletion(v models.CompletionReport, images []models.EmbeddedImage) (models.Artifact, error) {
	p := gofpdf.New("P", "mm", "A4", "")
	regular := fontPath(
		"REPORT_FONT_REGULAR",
		"assets/fonts/DejaVuSans.ttf",
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/TTF/DejaVuSans.ttf",
		"C:/Windows/Fonts/arial.ttf",
	)

	bold := fontPath(
		"REPORT_FONT_BOLD",
		"assets/fonts/DejaVuSans-Bold.ttf",
		"/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
		"/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
		"C:/Windows/Fonts/arialbd.ttf",
	)
	if regular == "" || bold == "" {
		return models.Artifact{}, fmt.Errorf("completion report fonts are unavailable")
	}
	p.AddUTF8Font("Report", "", regular)
	p.AddUTF8Font("Report", "B", bold)
	p.SetMargins(20, 18, 20)
	p.SetAutoPageBreak(true, 18)
	p.AddPage()
	p.SetTextColor(31, 72, 60)
	p.SetFont("Report", "B", 18)
	p.MultiCell(0, 9, "Отчёт о выполнении заявки", "", "L", false)
	p.SetFont("Report", "", 9)
	p.SetTextColor(91, 110, 104)
	p.Cell(0, 7, "Заявка "+v.Ticket.ID)
	p.Ln(12)

	field := func(label, value string) {
		p.SetFont("Report", "B", 9)
		p.SetTextColor(91, 110, 104)
		p.Cell(44, 7, label)
		p.SetFont("Report", "", 10)
		p.SetTextColor(28, 43, 39)
		p.MultiCell(0, 7, fallback(value, "Не указано"), "", "L", false)
		p.Ln(1)
	}
	field("Заявка", v.Ticket.Title)
	field("Адрес", v.Ticket.Address)
	field("Заявку открыл", v.OpenedBy)
	field("Бригада", fallback(v.Brigade.Name, v.Brigade.ID))
	members := make([]string, 0, len(v.Brigade.Members))
	for _, member := range v.Brigade.Members {
		name := fallback(member.FullName, member.UserID)
		if strings.TrimSpace(member.Role) != "" {
			name += " (" + member.Role + ")"
		}
		members = append(members, name)
	}
	field("Состав бригады", strings.Join(members, ", "))
	p.Ln(5)
	p.SetFillColor(239, 246, 242)
	p.SetTextColor(31, 72, 60)
	p.SetFont("Report", "B", 11)
	p.CellFormat(0, 9, "Описание выполненных работ", "", 1, "L", true, 0, "")
	p.SetFont("Report", "", 10)
	p.SetTextColor(28, 43, 39)
	p.SetFillColor(250, 252, 250)
	p.MultiCell(0, 7, fallback(v.Description, "Описание не указано"), "", "L", true)

	for index, item := range images {
		kind, width, height, ok := imageInfo(item)
		if !ok {
			continue
		}
		p.AddPage()
		p.SetFont("Report", "B", 11)
		p.SetTextColor(31, 72, 60)
		p.Cell(0, 8, fmt.Sprintf("Фотоматериал %d: %s", index+1, fallback(item.Name, "фото")))
		p.Ln(12)
		options := gofpdf.ImageOptions{ImageType: kind, ReadDpi: true}
		name := fmt.Sprintf("completion-image-%d", index)
		p.RegisterImageOptionsReader(name, options, bytes.NewReader(item.Data))
		maxW, maxH := 170.0, 235.0
		ratio := float64(width) / float64(height)
		w, h := maxW, maxW/ratio
		if h > maxH {
			h, w = maxH, maxH*ratio
		}
		p.ImageOptions(name, 20+(170-w)/2, p.GetY(), w, h, false, options, 0, "")
	}

	var out bytes.Buffer
	if err := p.Output(&out); err != nil {
		return models.Artifact{}, err
	}
	return models.Artifact{Name: "ticket-" + safe(v.Ticket.ID) + "-completion.pdf", ContentType: "application/pdf", Data: out.Bytes()}, nil
}

func fontPath(envName string, candidates ...string) string {
	if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
		if _, err := os.Stat(value); err == nil {
			return value
		}
	}
	for _, value := range candidates {
		if _, err := os.Stat(value); err == nil {
			return value
		}
	}
	return ""
}

func fallback(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func imageInfo(item models.EmbeddedImage) (string, int, int, bool) {
	contentType := strings.ToLower(strings.TrimSpace(item.ContentType))
	kind := map[string]string{"image/jpeg": "JPG", "image/jpg": "JPG", "image/png": "PNG", "image/gif": "GIF"}[contentType]
	if kind == "" {
		return "", 0, 0, false
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(item.Data))
	if err != nil || config.Width <= 0 || config.Height <= 0 {
		return "", 0, 0, false
	}
	return kind, config.Width, config.Height, true
}
