package main

import (
    "fmt"
    "log"

    "github.com/pdfcpu/pdfcpu/pkg/api"
    "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
    "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func ExtractTextFromPDF(filePath string) {
    conf := model.NewDefaultConfiguration()

    err := api.ExtractTextFile(filePath, "-", nil, conf)
    if err != nil {
        log.Fatalf("Error extracting text from PDF: %v", err)
    }

    fmt.Println("Text extraction complete.")
}

func main() {
    ExtractTextFromPDF("/data/black-magick/top_dnd_proj/go-server/internal/parser/rylikSat.pdf")
}

