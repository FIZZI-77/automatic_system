package generator

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"github.com/jung-kurt/gofpdf"
	"github.com/xuri/excelize/v2"
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
