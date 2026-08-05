package main

import (
	"os"
	"strings"
	"testing"
)

func TestScanSourceDoesNotOwnListPackagesImplementation(t *testing.T) {
	scanSource, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatalf("read scan.go: %v", err)
	}
	if strings.Contains(string(scanSource), "func runListPackagesWithSettings(") {
		t.Fatal("scan.go declares runListPackagesWithSettings; keep list-packages implementation in list_packages.go")
	}

	listPackagesSource, err := os.ReadFile("list_packages.go")
	if err != nil {
		t.Fatalf("read list_packages.go: %v", err)
	}
	if !strings.Contains(string(listPackagesSource), "func runListPackagesWithSettings(") {
		t.Fatal("list_packages.go must own runListPackagesWithSettings")
	}
}
