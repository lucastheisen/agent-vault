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
)

type serviceMatcher interface {
	Match(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*broker.Service, error)
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

	skip := scope.SkipFilter ||
		(scope.AgentID != "" && matched.Filter.AgentID != "" && scope.AgentID == matched.Filter.AgentID)
	if skip {
		return false
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
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_unreachable",
			"Service filter URL is invalid.")
		emit(http.StatusBadGateway, "filter_unreachable")
		return
	}

	rawToken := ""
	if p.filterTokens != nil && matched.Filter.AgentID != "" {
		rawToken, err = p.filterTokens.FilterAgentToken(r.Context(), matched.Filter.AgentID)
		if err != nil || rawToken == "" {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_agent_revoked",
				"Service filter agent is missing or revoked. Re-apply the filter configuration.")
			emit(http.StatusBadGateway, "filter_agent_revoked")
			return
		}
	} else if matched.Filter.AgentID == "" {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_agent_revoked",
			"Service filter is not provisioned. Re-apply the filter configuration.")
		emit(http.StatusBadGateway, "filter_agent_revoked")
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

	nonce := ""
	if p.tickets != nil {
		nonce, err = p.tickets.Mint(brokercore.ContinuationClaims{
			VaultID:       scope.VaultID,
			VaultName:     scope.VaultName,
			UserID:        scope.UserID,
			AgentID:       scope.AgentID,
			VaultRole:     scope.VaultRole,
			Method:        r.Method,
			Host:          host,
			Path:          r.URL.Path,
			FilterAgentID: matched.Filter.AgentID,
		})
		if err != nil {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_unreachable",
				"Failed to mint filter continuation ticket.")
			emit(http.StatusBadGateway, "filter_unreachable")
			return
		}
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
			if rawToken != "" {
				pr.Out.Header.Set(brokercore.HeaderFilterToken, rawToken)
			}
			if nonce != "" {
				pr.Out.Header.Set(brokercore.HeaderFilterNonce, nonce)
			}
			pr.Out.Header.Set(brokercore.HeaderService, matched.Name)
			vault := matched.Filter.Vault
			if vault == "" {
				vault = scope.VaultName
			}
			pr.Out.Header.Set(brokercore.HeaderFilterVault, vault)
		},
		FlushInterval: -1, // stream immediately (git packfiles, WS)
		Transport:     p.filterTransport,
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
			emit(resp.StatusCode, "")
			return nil
		},
	}
	rp.ServeHTTP(w, r)
}

func stripFilterHopHeaders(h http.Header) {
	for name := range h {
		if brokercore.IsBrokerScopedRequestHeader(name) {
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
