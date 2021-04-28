package dyndns

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

var (
	_ caddy.Module                = (*DynDnsHandler)(nil)
	_ caddy.Provisioner           = (*DynDnsHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*DynDnsHandler)(nil)
)

func init() {
	caddy.RegisterModule(&DynDnsHandler{})
}

// Handles a notification that an IP address has changed.
// On any request, checks the query parameters for IP addresses,
// then updates the domain given in the configuration.
//
// When any HTTP request is submitted, it checks for query parameters "4" and "6".
// For example, `GET /?4=123.234.210.2&6=2000:80::52:3` -
// this then updates the configured DNS provider with
// corresponding A and AAAA records.
// Either one or both of these parameters may be specified in a request.
// If the IPv6 address is given as a CIDR prefix (e.g. `/?6=2000:80::/64`),
// then the unmasked space is filled based on the address
// specified in the ipv6 field.
type DynDnsHandler struct {
	// The DNS provider module to use for updating the DNS records.
	// Note that providers that satisfy the requirements for ACME
	// don't necessarily work here.
	//
	// Providers that simply forward to libdns should be fine.
	ProviderRaw json.RawMessage `json:"provider" caddy:"namespace=dns.providers inline_key=name"`

	// The full domain name to get updated.
	Domain string `json:"domain"`

	// The DNS zone to update. This will likely be the root domain
	// that you purchased. If omitted, defaults to a suffix of the domain.
	// If specified, must be a suffix of the domain.
	//
	// Note that the suffix guesswork is currently very naïve -
	// the second-last component is considered to be the zone.
	// This doesn't always work - for example, the domain `sub.example.co.nz`
	// will produce a zone of `co.nz` (even though you would probably want
	// `example.co.nz`).
	Zone string `json:"zone,omitempty"`

	// An optional address to use, to override the local IPv6 address.
	// When specified, if a new IPv6 address only sets the high half
	// (i.e. the new address is a subnet range),
	// the low half will be filled with the matching low half
	// specified in this field.
	//
	// This can either be an IPv6 address,
	// or a domain name to look up
	// (may be useful within a Docker container).
	LanIPv6 string `json:"ipv6,omitempty"`

	Provider libdns.RecordSetter `json:"-"`
	logger   *zap.Logger
	localIP6 net.IP
}

func (*DynDnsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dyndns",
		New: func() caddy.Module { return new(DynDnsHandler) },
	}
}

func (ddns *DynDnsHandler) Provision(ctx caddy.Context) error {
	ddns.logger = ctx.Logger(ddns)

	val, err := ctx.LoadModule(ddns, "ProviderRaw")
	if err != nil {
		return fmt.Errorf("loading DNS provider module: %v", err)
	}

	if provider, ok := val.(libdns.RecordSetter); ok {
		ddns.Provider = provider
	} else {
		return fmt.Errorf("loading DNS provider module: doesn't implement RecordSetter")
	}

	if ddns.Zone == "" {
		lastDot := strings.LastIndexByte(ddns.Domain, '.')
		if lastDot == len(ddns.Domain)-1 {
			lastDot = strings.LastIndexByte(ddns.Domain[:lastDot], '.')
		}

		lastDot = strings.LastIndexByte(ddns.Domain[:lastDot], '.')
		ddns.Zone = ddns.Domain[lastDot+1:]
		ddns.Domain = ddns.Domain[:lastDot]
	} else if !strings.HasSuffix(ddns.Domain, "."+ddns.Zone) {
		return fmt.Errorf("configuring dyndns zone: .%s not a suffix of %s", ddns.Zone, ddns.Domain)
	} else {
		ddns.Domain = ddns.Domain[:len(ddns.Domain)-(len(ddns.Zone)+1)]
	}

	if ddns.LanIPv6 == "" {
		ddns.localIP6 = nil
	} else if ip6 := net.ParseIP(ddns.LanIPv6); ip6 != nil {
		ddns.localIP6 = ip6
	} else {
		ips, err := net.LookupIP(ddns.LanIPv6)
		if err != nil {
			return fmt.Errorf("finding IPv6 for LAN: %w", err)
		}

		ddns.localIP6 = nil
		for _, ip := range ips {
			if len(ip) == 16 {
				ddns.localIP6 = ip
				break
			}
		}

		if ddns.localIP6 == nil {
			return fmt.Errorf("finding IPv6 for LAN: no IPv6 addresses found for %q", ddns.LanIPv6)
		}
	}

	return nil
}

func (ddns *DynDnsHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, _ caddyhttp.Handler) error {
	q := req.URL.Query()

	records := []libdns.Record{}

	ipv4s := q.Get("4")
	if ipv4s != "" {
		ip4 := net.ParseIP(ipv4s)
		if ip4 == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("IPv4 address invalid"))
			ddns.logger.Info("bad IPv4 address submitted",
				zap.String("address", ipv4s))
			return nil
		}

		records = append(records, libdns.Record{
			Type:  "A",
			Name:  ddns.Domain,
			Value: ip4.String(),
		})
	}

	ipv6s := q.Get("6")
	if ipv6s != "" {
		ip6 := net.ParseIP(ipv6s)
		if ip6 == nil {
			_, ip6net, err := net.ParseCIDR(ipv6s)
			if err != nil {
				ddns.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("IPv6 address invalid"))
				return nil
			}

			prefixBits, _ := ip6net.Mask.Size()
			prefixBytes := prefixBits / 8
			if prefixBits%8 > 0 {
				prefixBytes++
			}

			ip6 = ip6net.IP
			copy(ip6[prefixBytes:], ddns.localIP6[prefixBytes:])
		}

		records = append(records, libdns.Record{
			Type:  "AAAA",
			Name:  ddns.Domain,
			Value: ip6.String(),
		})
	}

	if len(records) > 0 {
		_, err := ddns.Provider.SetRecords(req.Context(), ddns.Zone, records)
		if err != nil {
			ddns.logger.Error("failed to update DNS records",
				zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
