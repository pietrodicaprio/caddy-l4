package l4ldap

import (
	"encoding/json"
	"fmt"
	"gopkg.in/ldap.v2"
	"net/http"
	"strings"

	"crypto/tls"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&LDAPProxyHandler{})
}

type LDAPRoute struct {
	Server       string `json:"server"`
	BaseDN       string `json:"base_dn"`
	SearchFilter string `json:"search_filter"`
}

// LDAPProxyHandler is a handler that proxies LDAP requests based on the username.
type LDAPProxyHandler struct {
	Routes map[string]LDAPRoute `json:"routes,omitempty"`
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*LDAPProxyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ldap_proxy",
		New: func() caddy.Module { return new(LDAPProxyHandler) },
	}
}

// Provision sets up the handler.
func (h *LDAPProxyHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	return nil
}

// ServeHTTP handles the HTTP request.
func (h *LDAPProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	username := r.FormValue("username")
	if username == "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("username is required"))
	}

	// Extract domain from username if present
	var domain string
	if strings.Contains(username, "@") {
		parts := strings.Split(username, "@")
		username = parts[0]
		domain = parts[1]
	}

	// Determine the LDAP server based on the domain
	ldapServer, ok := h.Routes[domain]
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("no LDAP server found for domain: %s", domain))
	}

	// Proxy the request to the determined LDAP server
	err := h.proxyToLDAPServer(ldapServer, username, w, r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	return nil
}

// proxyToLDAPServer proxies the request to the specified LDAP server.
func (h *LDAPProxyHandler) proxyToLDAPServer(ldapRoute LDAPRoute, username string, w http.ResponseWriter, r *http.Request) error {
	// Create a connection to the LDAP server
	l, err := ldap.DialTLS("tcp", ldapRoute.Server, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		h.logger.Error("Failed to connect to LDAP server", zap.String("ldapRoute", ldapRoute.Server), zap.Error(err))
		return fmt.Errorf("failed to connect to LDAP server: %v", err)
	}
	defer l.Close()

	// Bind with the provided username and password
	password := r.FormValue("password")
	if password == "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("password is required"))
	}

	err = l.Bind(username, password)
	if err != nil {
		h.logger.Error("Failed to bind to LDAP server", zap.String("username", username), zap.Error(err))
		return fmt.Errorf("failed to bind to LDAP server: %v", err)
	}

	// Perform an LDAP search to find the DN using sAMAccountName
	searchRequest := ldap.NewSearchRequest(
		ldapRoute.BaseDN, // The base DN for the search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", username), // The filter to apply
		[]string{"dn"}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		h.logger.Error("Failed to search LDAP server", zap.String("username", username), zap.Error(err))
		return fmt.Errorf("failed to search LDAP server: %v", err)
	}

	// Marshal the search result to JSON
	jsonResponse, err := json.Marshal(sr.Entries)
	if err != nil {
		h.logger.Error("Failed to marshal LDAP response", zap.Error(err))
		return fmt.Errorf("failed to marshal LDAP response: %v", err)
	}

	// Write the JSON response back to the HTTP response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)

	h.logger.Info("Successfully proxied request to LDAP server", zap.String("ldapRoute", ldapRoute.Server), zap.String("username", username))
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (h *LDAPProxyHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	h.Routes = make(map[string]LDAPRoute)
	for d.Next() {
		var domain, server, baseDN, searchFilter string
		if !d.Args(&domain, &server, &baseDN, &searchFilter) {
			return d.ArgErr()
		}
		h.Routes[domain] = LDAPRoute{
			Server:       server,
			BaseDN:       baseDN,
			SearchFilter: searchFilter,
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*LDAPProxyHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*LDAPProxyHandler)(nil)
	_ caddyfile.Unmarshaler       = (*LDAPProxyHandler)(nil)
)
