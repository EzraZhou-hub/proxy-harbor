package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Called only after main's isolated-guest and fixed-target checks. It can
// launch only this exact temporary fixture, never an installed application.
func runChildFixture(depth int, target, api string, helper bool) {
	executable, err := os.Executable()
	if err != nil || (!strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\bin\proxy-harbor-p0-probe.exe`) && !strings.EqualFold(filepath.Clean(executable), `C:\P0Lab\.local\p0\bin\helpers\proxy-harbor-p0-helper.exe`)) {
		emit(false, "child fixture executable must be the exact isolated probe")
		return
	}
	if helper {
		executable = `C:\P0Lab\.local\p0\bin\helpers\proxy-harbor-p0-helper.exe`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-transparent-target", target, "-resolve-api", api, "-spawn-depth", strconv.Itoa(depth-1), "-use-helper="+strconv.FormatBool(helper))
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		if len(output) > 4096 {
			output = output[:4096]
		}
		emit(false, fmt.Sprintf("child fixture failed: %v; bounded fixture output: %s", err, output))
		return
	}
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		var result struct {
			Success   bool  `json:"success"`
			PIDs      []int `json:"pids"`
			Container bool  `json:"zeroCapabilityAppContainer"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &result) != nil || !result.Success || len(result.PIDs) != depth {
			continue
		}
		if os.Getenv("P0_REQUIRE_APP_CONTAINER") == "1" && (!result.Container || !verifiedAppContainer()) {
			emit(false, "child did not preserve the required AppContainer identity")
			return
		}
		seen := map[int]bool{os.Getpid(): true}
		for _, pid := range result.PIDs {
			if pid <= 0 || seen[pid] {
				emit(false, "invalid child process evidence")
				return
			}
			seen[pid] = true
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "detail": "child fixture completed", "pids": append([]int{os.Getpid()}, result.PIDs...), "zeroCapabilityAppContainer": verifiedAppContainer()})
		return
	}
	emit(false, "child did not return a successful process chain")
}
