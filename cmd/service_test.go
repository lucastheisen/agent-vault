package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestLoadServicesFromFileFilterOps(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	omit, err := loadServicesFromFile(write("omit.yaml", `
services:
  - name: s
    host: h.example
    auth:
      type: passthrough
`), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if omit[0].FilterOp != broker.FilterOpOmit || omit[0].Filter != nil {
		t.Fatalf("omit: op=%d filter=%v", omit[0].FilterOp, omit[0].Filter)
	}

	set, err := loadServicesFromFile(write("set.yaml", `
services:
  - name: s
    host: h.example
    auth:
      type: passthrough
    filter:
      url: http://127.0.0.1:12345
      vault: policy
`), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if set[0].FilterOp != broker.FilterOpSet || set[0].Filter == nil || set[0].Filter.URL != "http://127.0.0.1:12345" {
		t.Fatalf("set: %+v op=%d", set[0].Filter, set[0].FilterOp)
	}

	clr, err := loadServicesFromFile(write("null.yaml", `
services:
  - name: s
    host: h.example
    auth:
      type: passthrough
    filter: null
`), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if clr[0].FilterOp != broker.FilterOpClear || clr[0].Filter != nil {
		t.Fatalf("null: op=%d filter=%v", clr[0].FilterOp, clr[0].Filter)
	}

	empty, err := loadServicesFromFile(write("empty.yaml", `
services:
  - name: s
    host: h.example
    auth:
      type: passthrough
    filter: {}
`), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if empty[0].FilterOp != broker.FilterOpClear {
		t.Fatalf("empty object should clear, op=%d", empty[0].FilterOp)
	}
}
