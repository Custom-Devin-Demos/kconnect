/*
Copyright 2020 The kconnect Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestDoDoesNotLogSecrets(t *testing.T) {
	const responseBody = `{"access_token":"secret-access-token","refresh_token":"secret-refresh-token"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret-cookie"})
		fmt.Fprint(w, responseBody)
	}))
	defer server.Close()

	core, logs := observer.New(zapcore.DebugLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	defer restore()

	headers := map[string]string{"cookie": "secret-req-cookie"}
	SetBasicAuthHeaders(headers, "alice", "secret-password")

	client := NewHTTPClient()
	resp, err := client.Get(server.URL, headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Body() != responseBody {
		t.Fatalf("expected body %q, got %q", responseBody, resp.Body())
	}

	if logs.Len() == 0 {
		t.Fatal("expected debug logs to be written")
	}

	secrets := []string{headers["Authorization"], "secret-req-cookie", "secret-cookie", "secret-access-token", "secret-refresh-token"}
	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += fmt.Sprintf(" %s=%v", k, v)
		}
		for _, secret := range secrets {
			if strings.Contains(line, secret) {
				t.Errorf("log entry %q contains secret %q", line, secret)
			}
		}
	}
}

func TestRedactHeaders(t *testing.T) {
	in := map[string]string{
		"Authorization": "Bearer token",
		"Cookie":        "a=b",
		"Content-Type":  MediaTypeJSON,
	}

	out := redactHeaders(in)

	if out["Authorization"] != redactedValue || out["Cookie"] != redactedValue {
		t.Errorf("expected sensitive headers to be redacted, got %v", out)
	}
	if out["Content-Type"] != MediaTypeJSON {
		t.Errorf("expected non-sensitive header to be kept, got %v", out)
	}
	if in["Authorization"] != "Bearer token" {
		t.Error("input headers must not be modified")
	}
}
