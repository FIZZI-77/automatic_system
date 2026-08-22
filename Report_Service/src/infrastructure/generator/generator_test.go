package generator

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"os"
	"report/models"
	"strings"
	"testing"
)

func TestFormats(t *testing.T) {
	for _, f := range []models.Format{models.FormatCSV, models.FormatXLSX, models.FormatPDF} {
		a, e := New().Generate(f, "test", [][]string{{"name", "value"}, {"created", "10"}})
		if e != nil {
			t.Fatalf("%s: %v", f, e)
		}
		if len(a.Data) == 0 || a.ContentType == "" {
			t.Fatalf("empty %s artifact", f)
		}
	}
}

func TestCompletionReport(t *testing.T) {
	photo := image.NewRGBA(image.Rect(0, 0, 640, 360))
	for y := 0; y < 360; y++ {
		for x := 0; x < 640; x++ {
			photo.Set(x, y, color.RGBA{R: uint8(90 + x/8), G: uint8(130 + y/5), B: 110, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, photo); err != nil {
		t.Fatal(err)
	}
	var encodedGIF bytes.Buffer
	if err := gif.Encode(&encodedGIF, photo, nil); err != nil {
		t.Fatal(err)
	}
	artifact, err := New().GenerateCompletion(models.CompletionReport{
		WorkReportID: "8e5758f0-8cc4-4404-b879-25aac8a77c5f",
		RequestedBy:  "83e3752a-6ca4-4bdd-9e0d-581493f140c7",
		Ticket:       models.CompletionTicket{ID: "INC-1042", Title: "Повреждение водопровода", Address: "Москва, ул. Большая Дмитровка, 18"},
		Brigade:      models.CompletionBrigade{ID: "BR-14", Name: "Аварийная бригада №14", Members: []models.CompletionBrigadeMember{{FullName: "Сергей Петров", Role: "руководитель"}, {FullName: "Антон Волков", Role: "специалист"}}},
		OpenedBy:     "Анна Соколова",
		Description:  "Перекрыта подача воды, заменён повреждённый участок трубы, соединения проверены под рабочим давлением. Течь устранена.",
	}, []models.EmbeddedImage{{Name: "результат-работ.png", ContentType: "image/png", Data: encoded.Bytes()}, {Name: "результат-работ.gif", ContentType: "image/gif", Data: encodedGIF.Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Data) < 10_000 || !strings.HasPrefix(string(artifact.Data[:4]), "%PDF") {
		t.Fatalf("invalid completion PDF: %d bytes", len(artifact.Data))
	}
	if output := os.Getenv("COMPLETION_REPORT_SAMPLE_PATH"); output != "" {
		if err := os.WriteFile(output, artifact.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
