// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"strings"
	"testing"
)

func TestGroupSignRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request GroupSignRequest
		wantErr string
	}{
		{name: "sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}},
		{name: "mixed sign and foreign", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe"}}}},
		{name: "passthrough mode", request: GroupSignRequest{Requests: []SignRequest{{SignedTxnHex: "cafebabe"}}}},
		{
			name: "invalid empty entry",
			request: GroupSignRequest{Requests: []SignRequest{
				{AuthAddress: "AUTH", TxnBytesHex: "deadbeef"},
				{},
			}},
			wantErr: "transaction 2: must specify either sign fields",
		},
		{name: "all foreign", request: GroupSignRequest{Requests: []SignRequest{{TxnBytesHex: "deadbeef"}}}, wantErr: "no signable transactions: all entries are foreign"},
		{
			name: "mixed passthrough and foreign",
			request: GroupSignRequest{Requests: []SignRequest{
				{SignedTxnHex: "cafebabe"},
				{TxnBytesHex: "deadbeef"},
			}},
			wantErr: "cannot mix passthrough and foreign transactions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
