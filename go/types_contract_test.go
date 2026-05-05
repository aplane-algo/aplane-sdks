// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var expectedSDKContractFixtureNames = []string{
	"admin_delete_response_success.json",
	"admin_generate_request_generic.json",
	"admin_generate_response_generic.json",
	"error_response.json",
	"group_plan_response_mutated.json",
	"group_sign_request_mixed.json",
	"group_sign_response_mutated.json",
	"health_response_ready.json",
	"keys_response_generic.json",
	"keytypes_response_full.json",
}

func sdkContractFixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Join(filepath.Dir(file), "..", "contracts", "signerapi", name)
}

func sdkContractFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Dir(sdkContractFixturePath(t, "README.md"))
}

func committedSDKContractFixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(sdkContractFixtureDir(t))
	if err != nil {
		t.Fatalf("read contract fixture dir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func assertSDKContractRoundTrip[T any](t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(sdkContractFixturePath(t, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("unmarshal %s into SDK type: %v", name, err)
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s from SDK type: %v", name, err)
	}

	var want any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("unmarshal fixture %s as generic JSON: %v", name, err)
	}
	var got any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal round-tripped %s as generic JSON: %v", name, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch for %s\nwant: %#v\n got: %#v", name, want, got)
	}
}

func TestGoSDKContractFixturesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, string)
	}{
		{"group_sign_request_mixed.json", assertSDKContractRoundTrip[GroupSignRequest]},
		{"group_sign_response_mutated.json", assertSDKContractRoundTrip[GroupSignResponse]},
		{"group_plan_response_mutated.json", assertSDKContractRoundTrip[PlanGroupResponse]},
		{"keys_response_generic.json", assertSDKContractRoundTrip[KeysResponse]},
		{"keytypes_response_full.json", assertSDKContractRoundTrip[KeyTypesResponse]},
		{"admin_generate_request_generic.json", assertSDKContractRoundTrip[generateRequest]},
		{"admin_generate_response_generic.json", assertSDKContractRoundTrip[GenerateResult]},
		{"health_response_ready.json", assertSDKContractRoundTrip[HealthResponse]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, tt.name)
		})
	}
}

func TestGoSDKContractFixtureManifest(t *testing.T) {
	if got := committedSDKContractFixtureNames(t); !reflect.DeepEqual(got, expectedSDKContractFixtureNames) {
		t.Fatalf("contract fixture manifest mismatch\nwant: %#v\n got: %#v", expectedSDKContractFixtureNames, got)
	}
	for _, name := range expectedSDKContractFixtureNames {
		raw, err := os.ReadFile(sdkContractFixturePath(t, name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("fixture %s is not valid JSON: %v", name, err)
		}
	}
}
