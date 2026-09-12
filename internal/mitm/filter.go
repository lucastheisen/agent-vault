package mitm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

type serviceMatcher interface {
	Match(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*broker.Service, error)
}

type vaultLookup interface {
	LookupVault(ctx context.Context, name string) (*store.Vault, error)
}

func (p *Proxy) maybeForwardFilter(
	w http.ResponseWriter,
	r *http.Request,
	target, host string,
	port int,
	useTLSUpstream bool,
	scope *brokercore.ProxyScope,
	emit func(status int, errCode string),
) bool {
	matcher, ok := p.creds.(serviceMatcher)
	if !ok {
		return false
	}
	matched, err := matcher.Match(r.Context(), scope.VaultID, host, port, r.URL.Path)
	if err != nil || matched == nil || !matched.HasActiveFilter() {
		return false
	}
	if !matched.IsEnabled() {
		return false
	}

	if scope.SkipFilter {
		return false
	}
	if scope.IsPolicy {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"Policy capability cannot invoke a filtered service.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return true
	}

	p.reverseProxyToFilter(w, r, target, host, useTLSUpstream, scope, matched, emit)
	return true
}

func (p *Proxy) reverseProxyToFilter(
	w http.ResponseWriter,
	r *http.Request,
	target, host string,
	useTLSUpstream bool,
	scope *brokercore.ProxyScope,
	matched *broker.Service,
	emit func(status int, errCode string),
) {
	filterURL, err := url.Parse(matched.Filter.URL)
	if err != nil || filterURL.Host == "" {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"Service filter URL is invalid.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}
	if err := broker.ValidateFilter(matched.Filter); err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"Service filter URL is not allowed.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}

	scheme := "http"
	if useTLSUpstream {
		scheme = "https"
	}
	origURL := &url.URL{
		Scheme:   scheme,
		Host:     hostHeaderForScheme(scheme, target),
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	bind := brokercore.BindFromURL(r.Method, origURL)

	if p.caps == nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"Filter capabilities are not configured.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}

	contRec := brokercore.Capability{
		SourceVaultID: scope.VaultID,
		ActorUserID:   scope.UserID,
		ActorAgentID:  scope.AgentID,
		SourceSessID:  scope.SourceSessID,
		VaultRole:     scope.VaultRole,
		VaultName:     scope.VaultName,
		Method:        bind.Method,
		Scheme:        bind.Scheme,
		Authority:     bind.Authority,
		EscapedPath:   bind.EscapedPath,
		Query:         bind.Query,
		Snapshot:      brokercore.SnapshotFromService(matched),
	}
	contToken, err := p.caps.IssueContinuation(r.Context(), contRec)
	if err != nil || contToken == "" {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"Failed to issue filter continuation.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}

	var polToken string
	if pvName := matched.Filter.PolicyVault; pvName != "" {
		polRec := contRec
		polRec.Snapshot = brokercore.MatchSnapshot{Version: 1}
		if pvName == scope.VaultName {
			polRec.PolicyVaultID = scope.VaultID
			polRec.PolicyVaultName = scope.VaultName
		} else if lu, ok := p.sessions.(vaultLookup); ok {
			v, verr := lu.LookupVault(r.Context(), pvName)
			if verr != nil || v == nil {
				brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
					"Filter policy_vault could not be resolved.")
				emit(http.StatusBadGateway, "filter_misconfigured")
				return
			}
			polRec.PolicyVaultID = v.ID
			polRec.PolicyVaultName = v.Name
		} else {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
				"Filter policy_vault could not be resolved.")
			emit(http.StatusBadGateway, "filter_misconfigured")
			return
		}
		polToken, err = p.caps.IssuePolicy(r.Context(), polRec)
		if err != nil || polToken == "" {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
				"Failed to issue filter policy capability.")
			emit(http.StatusBadGateway, "filter_misconfigured")
			return
		}
	}

	proxyURL := p.advertisedProxyURL()
	caPEM := ""
	if p.ca != nil {
		caPEM = strings.ReplaceAll(string(p.RootPEM()), "\n", "")
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := *filterURL
			if out.Path == "" || out.Path == "/" {
				out.Path = r.URL.Path
				out.RawPath = r.URL.RawPath
			} else {
				out.Path = strings.TrimRight(out.Path, "/") + r.URL.Path
			}
			out.RawQuery = r.URL.RawQuery
			pr.Out.URL = &out
			pr.Out.Host = origURL.Host
			stripFilterHopHeaders(pr.Out.Header)
			pr.Out.Header.Set(brokercore.HeaderOriginalURL, origURL.String())
			pr.Out.Header.Set(brokercore.HeaderContinuationProxy, proxyURL)
			pr.Out.Header.Set(brokercore.HeaderContinuationToken, contToken)
			if polToken != "" {
				pr.Out.Header.Set(brokercore.HeaderPolicyProxy, proxyURL)
				pr.Out.Header.Set(brokercore.HeaderPolicyToken, polToken)
			}
			if caPEM != "" {
				pr.Out.Header.Set(brokercore.HeaderCA, caPEM)
			}
			pr.Out.Header.Set(brokercore.HeaderService, matched.Name)
		},
		FlushInterval: -1,
		Transport:     filterTransport(matched.Filter),
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, e error) {
			status := http.StatusBadGateway
			code := "filter_unreachable"
			if isTimeoutErr(e) {
				status = http.StatusGatewayTimeout
				code = "filter_timeout"
			}
			brokercore.WriteProxyError(rw, status, code,
				fmt.Sprintf("Service filter at %s is unreachable.", matched.Filter.URL))
			emit(status, code)
		},
		ModifyResponse: func(resp *http.Response) error {
			stripAgentVaultResponseHeaders(resp.Header)
			emit(resp.StatusCode, "")
			return nil
		},
	}
	rp.ServeHTTP(w, r)
}

func (p *Proxy) advertisedProxyURL() string {
	if p.filterProxyURL != "" {
		return p.filterProxyURL
	}
	addr := p.boundAddr
	if addr == "" {
		addr = p.httpServer.Addr
	}
	return "http://" + addr
}

func stripFilterHopHeaders(h http.Header) {
	for name := range h {
		if brokercore.IsBrokerScopedRequestHeader(name) {
			h.Del(name)
		}
	}
}

func stripAgentVaultResponseHeaders(h http.Header) {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Agent-Vault-") {
			h.Del(name)
		}
	}
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}
