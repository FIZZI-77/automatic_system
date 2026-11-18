// Command coveragecheck enforces package statement coverage from a Go cover profile.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

type block struct {
	statements int64
	covered    bool
}

func main() {
	profile := flag.String("profile", "coverage.out", "Go cover profile")
	config := flag.String("config", "coverage-gates.json", "package thresholds by module")
	module := flag.String("module", "", "module directory")
	flag.Parse()
	if err := run(*profile, *config, *module, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(profile, config, module string, out io.Writer) error {
	data, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	var gates map[string]map[string]float64
	if err := json.Unmarshal(data, &gates); err != nil {
		return err
	}
	thresholds, ok := gates[module]
	if !ok || len(thresholds) == 0 {
		return fmt.Errorf("no coverage gates configured for module %q", module)
	}
	f, err := os.Open(profile)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // Closing a read-only profile cannot change its contents.
	return check(f, thresholds, out)
}

func check(r io.Reader, gates map[string]float64, out io.Writer) error {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() || (scanner.Text() != "mode: atomic" && scanner.Text() != "mode: count" && scanner.Text() != "mode: set") {
		return fmt.Errorf("missing or invalid cover mode")
	}
	blocks := make(map[string]block)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !strings.Contains(fields[0], ":") {
			return fmt.Errorf("invalid cover record %q", scanner.Text())
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid statement count %q", fields[1])
		}
		count, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || count < 0 {
			return fmt.Errorf("invalid execution count %q", fields[2])
		}
		previous, exists := blocks[fields[0]]
		if exists && previous.statements != n {
			return fmt.Errorf("conflicting statement count for %s", fields[0])
		}
		blocks[fields[0]] = block{statements: n, covered: count > 0 || previous.covered}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	var failed bool
	for pkg, minimum := range gates {
		if minimum <= 0 || minimum > 100 {
			return fmt.Errorf("invalid coverage threshold for %s: %g", pkg, minimum)
		}
		var total, covered int64
		for location, b := range blocks {
			file, _, _ := strings.Cut(location, ":")
			if path.Dir(file) == pkg {
				total += b.statements
				if b.covered {
					covered += b.statements
				}
			}
		}
		if total == 0 {
			return fmt.Errorf("coverage profile is missing statements for %s", pkg)
		}
		percent := float64(covered) * 100 / float64(total)
		if _, err := fmt.Fprintf(out, "%s: %.2f%% (minimum %.2f%%)\n", pkg, percent, minimum); err != nil {
			return fmt.Errorf("write coverage result: %w", err)
		}
		if percent < minimum {
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("coverage gate failed")
	}
	return nil
}
