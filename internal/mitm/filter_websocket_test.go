package mitm

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

// wsEchoOrigin is a plain-HTTP WebSocket origin that echoes one text
// frame back with an "echo:" prefix, and records the credential it was
// handed.
func wsEchoOrigin(t *testing.T, hits *atomic.Int32, sawAuth *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}
		hits.Add(1)
		sawAuth.Store(r.Header.Get("Authorization"))
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(buf,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = buf.Flush()
		frame, ferr := readWebSocketTextFrame(buf.Reader)
		if ferr != nil {
			return
		}
		_ = writeWebSocketTextFrame(conn, "echo:"+frame, false)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setupFilteredWS wires an http origin behind a filtered service and
// returns the proxy URL plus the counters.
func setupFilteredWS(t *testing.T, originURL, sidecarURL string) (*url.URL, *fakeCapStore, *atomic.Int32) {
	t.Helper()
	authority := strings.TrimPrefix(originURL, "http://")
	host, _, _ := net.SplitHostPort(authority)

	caps := newFakeCapStore()
	caps.addVault("vault-dev", "dev")

	svc := filteredSvc("ws-service", host, sidecarURL, "")
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {
			service: svc,
			result: &brokercore.InjectResult{
				MatchedName: "ws-service",
				Headers:     map[string]string{"Authorization": "Bearer dest-secret"},
			},
		},
	}}
	resolves := &atomic.Int32{}
	counting := &countingCredProvider{fakeCredProvider: cp, resolves: resolves}

	sr := validTokenResolver(filterTestToken, filterScope())
	proxyURL, _, _ := setupProxy(t, sr, counting, func(o *Options) {
		o.Filter = &FilterOptions{Store: caps, Authority: &fakeAuthority{}}
	})
	return proxyURL, caps, resolves
}

// wsUpgradeThroughProxy sends an absolute-form upgrade request and
// returns the proxy's response.
func wsUpgradeThroughProxy(t *testing.T, proxyURL *url.URL, token, target, clientKey string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn := dialProxy(t, proxyURL)
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(token + ":"))
	fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		target, u.Host, auth, clientKey)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return conn, reader, resp
}

func testWSKey() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i + 7)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// A filtered WebSocket upgrade goes to the sidecar, and a sidecar that
// refuses it costs no credential read and never reaches the origin.
func TestFilteredWebSocketDenied(t *testing.T) {
	var originHits atomic.Int32
	var sawAuth atomic.Value
	origin := wsEchoOrigin(t, &originHits, &sawAuth)

	var sawUpgrade atomic.Value
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUpgrade.Store(r.Header.Get("Upgrade"))
		// A sidecar may spoof nothing back at the agent.
		w.Header().Set(HeaderContinuationToken, "leaked")
		w.Header().Set("X-Sidecar", "denied")
		http.Error(w, "websocket not permitted", http.StatusForbidden)
	}))
	defer sidecar.Close()

	proxyURL, _, resolves := setupFilteredWS(t, origin.URL, sidecar.URL)

	conn, _, resp := wsUpgradeThroughProxy(t, proxyURL, filterTestToken, origin.URL+"/ws", testWSKey())
	defer conn.Close()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want the sidecar's 403", resp.StatusCode)
	}
	if got, _ := sawUpgrade.Load().(string); !strings.EqualFold(got, "websocket") {
		t.Errorf("sidecar saw Upgrade = %q, want the handshake reverse-proxied to it", got)
	}
	if resp.Header.Get("X-Sidecar") != "denied" {
		t.Error("ordinary sidecar headers must reach the client")
	}
	if got := resp.Header.Get(HeaderContinuationToken); got != "" {
		t.Errorf("%s = %q leaked to the client", HeaderContinuationToken, got)
	}
	if got := originHits.Load(); got != 0 {
		t.Errorf("origin saw %d upgrades, want 0", got)
	}
	if got := resolves.Load(); got != 0 {
		t.Errorf("ResolveMatch ran %d times, want 0", got)
	}
}

// The allow path: the sidecar opens its own WebSocket through the
// continuation and bridges the two streams. The origin sees the
// injected destination credential; frames flow end to end.
func TestFilteredWebSocketBridged(t *testing.T) {
	var originHits atomic.Int32
	var sawAuth atomic.Value
	origin := wsEchoOrigin(t, &originHits, &sawAuth)

	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		continuation := r.Header.Get(HeaderContinuationToken)
		callback := r.Header.Get(HeaderContinuationProxy)
		targetURL := r.Header.Get(HeaderOriginalURL)
		if continuation == "" || callback == "" {
			http.Error(w, "missing capability", http.StatusInternalServerError)
			return
		}

		clientConn, clientBuf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer clientConn.Close()

		// Open a fresh WebSocket to the exact original target, through
		// Agent Vault, using the continuation.
		cbURL, perr := url.Parse(callback)
		if perr != nil {
			return
		}
		upstream, derr := net.Dial("tcp", cbURL.Host)
		if derr != nil {
			return
		}
		defer upstream.Close()

		tu, _ := url.Parse(targetURL)
		auth := base64.StdEncoding.EncodeToString([]byte(continuation + ":"))
		fmt.Fprintf(upstream,
			"GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n"+
				"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
			targetURL, tu.Host, auth, r.Header.Get("Sec-WebSocket-Key"))

		upstreamBuf := bufio.NewReader(upstream)
		upResp, rerr := http.ReadResponse(upstreamBuf, &http.Request{Method: http.MethodGet})
		if rerr != nil || upResp.StatusCode != http.StatusSwitchingProtocols {
			fmt.Fprint(clientBuf, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			_ = clientBuf.Flush()
			return
		}

		// Complete the client-side handshake, then bridge.
		fmt.Fprintf(clientBuf,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = clientBuf.Flush()

		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, clientBuf); done <- struct{}{} }()
		go func() { _, _ = io.Copy(clientConn, upstreamBuf); done <- struct{}{} }()
		<-done
	}))
	defer sidecar.Close()

	proxyURL, _, resolves := setupFilteredWS(t, origin.URL, sidecar.URL)

	clientKey := testWSKey()
	conn, reader, resp := wsUpgradeThroughProxy(t, proxyURL, filterTestToken, origin.URL+"/ws", clientKey)
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 101 (body %q)", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != websocketAccept(clientKey) {
		t.Errorf("Sec-WebSocket-Accept = %q", got)
	}

	if err := writeWebSocketTextFrame(conn, "hi", true); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got, err := readWebSocketTextFrame(reader)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if got != "echo:hi" {
		t.Errorf("frame = %q, want echo:hi", got)
	}

	if n := originHits.Load(); n != 1 {
		t.Errorf("origin saw %d upgrades, want 1", n)
	}
	if a, _ := sawAuth.Load().(string); a != "Bearer dest-secret" {
		t.Errorf("origin Authorization = %q, want the injected destination credential", a)
	}
	if n := resolves.Load(); n != 1 {
		t.Errorf("ResolveMatch ran %d times, want exactly 1 (on the continuation)", n)
	}
}

// An unfiltered service keeps today's direct-to-origin WebSocket path.
func TestUnfilteredWebSocketBypassesTheFilterEntirely(t *testing.T) {
	var originHits atomic.Int32
	var sawAuth atomic.Value
	origin := wsEchoOrigin(t, &originHits, &sawAuth)

	var sidecarHits atomic.Int32
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sidecarHits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer sidecar.Close()

	authority := strings.TrimPrefix(origin.URL, "http://")
	host, _, _ := net.SplitHostPort(authority)

	caps := newFakeCapStore()
	caps.addVault("vault-dev", "dev")
	// Same host, but no filter block on the service.
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {
			service: &broker.Service{Name: "ws-service", Host: host},
			result: &brokercore.InjectResult{
				MatchedName: "ws-service",
				Headers:     map[string]string{"Authorization": "Bearer dest-secret"},
			},
		},
	}}
	sr := validTokenResolver(filterTestToken, filterScope())
	proxyURL, _, _ := setupProxy(t, sr, cp, func(o *Options) {
		o.Filter = &FilterOptions{Store: caps, Authority: &fakeAuthority{}}
	})

	clientKey := testWSKey()
	conn, reader, resp := wsUpgradeThroughProxy(t, proxyURL, filterTestToken, origin.URL+"/ws", clientKey)
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if err := writeWebSocketTextFrame(conn, "hi", true); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if got, err := readWebSocketTextFrame(reader); err != nil || got != "echo:hi" {
		t.Fatalf("frame = %q, err = %v", got, err)
	}
	if n := sidecarHits.Load(); n != 0 {
		t.Errorf("sidecar saw %d requests for an unfiltered service, want 0", n)
	}
	if n := originHits.Load(); n != 1 {
		t.Errorf("origin saw %d upgrades, want 1", n)
	}
}
