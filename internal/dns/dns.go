// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dns implements a DNS forwarder.
package dns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rtr7/router7/internal/dhcp4d"
	"github.com/rtr7/router7/internal/diag"
	"github.com/rtr7/router7/internal/teelogger"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

var log = teelogger.NewConsole()

// lcHostname is a string type used for lower-cased hostnames so that the
// DHCP-based local name resolution can be made case-insensitive.
type lcHostname string

type DNSClient struct {
	udp    *dns.Client
	tcp    *dns.Client
	http   *dohClient
	dialer *net.Dialer
	// TODO: Make cache either here or on Server. If on here we also need to allow bypassing the cache here...
}
var d net.Dialer

func DialContext(preResolved map[string]string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if addr, ok := preResolved[address]; ok {
			address = addr
		}
		return d.DialContext(ctx, network, address)
	}

}
func NewDNSClient(dohMap map[string]string) *DNSClient {
	if dohMap == nil {
		dohMap = make(map[string]string)
	}
	return &DNSClient{
		udp: &dns.Client{},
		tcp: &dns.Client{Net: "tcp"},
		http: &dohClient{
			http: http.Client{
				Transport: &http.Transport{
					Proxy:                 http.ProxyFromEnvironment,
					DialContext:           DialContext(dohMap),
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
				Timeout: 30 * time.Second,
			},
		},
	}
}

func (d *DNSClient) Exchange(m *dns.Msg, address string, clientInfo map[string]string) (*dns.Msg, time.Duration, error) {
	var (
		in  *dns.Msg
		rtt time.Duration
		err error
		uri *url.URL
	)
	if strings.HasPrefix(address, "https") {
		uri, err = url.Parse(address)
		if err != nil {
			return nil, -1, err
		}
		uri.Fragment=""
		values := uri.Query()
		for key, value := range clientInfo {
			values.Set(key, value)
		}
		uri.RawQuery = values.Encode()
		in, rtt, err = d.http.Exchange(m, uri.String())
		if err != nil {
			return nil, -1, err // fall back to next-slower upstream
		}
	} else {
		in, rtt, err = d.udp.Exchange(m, address)
		if err != nil {
			return nil, -1, err // fall back to next-slower upstream
		}
	}
	if in.Truncated {
		// Truncated response (exceeds UDP packet size), retry over TCP:
		// https://www.rfc-editor.org/rfc/rfc2181#section-9
		in, rtt, err = d.tcp.Exchange(m, address)
		if err != nil {
			return nil, -1, err
		}
	}
	return in, rtt, nil
}

type Server struct {
	Mux       *dns.ServeMux
	client    *DNSClient
	domain    string
	sometimes *rate.Limiter
	prom      struct {
		registry  *prometheus.Registry
		queries   prometheus.Counter
		upstream  *prometheus.CounterVec
		questions prometheus.Histogram
	}

	mu           sync.Mutex
	hostname, ip string
	hostsByName  map[lcHostname]string
	hostsByIP    map[string]string
	subnames     map[lcHostname]map[string]net.IP // hostname → subname → ip

	upstreamMu sync.RWMutex
	upstream   Upstreams
}

type Upstreams struct {
	Primary   []string
	Secondary []string
}

func NewServer(addr, domain string, upstream Upstreams) *Server {
	domain = strings.ToLower(domain)
	hostname, _ := os.Hostname()
	ip, _, _ := net.SplitHostPort(addr)
	if len(upstream.Primary) < 1 {
		upstream = Upstreams{Primary: []string{
			// https://developers.google.com/speed/public-dns/docs/using#google_public_dns_ip_addresses
			"8.8.8.8:53",
			"8.8.4.4:53",
			"[2001:4860:4860::8888]:53",
			"[2001:4860:4860::8844]:53",
		}}
	}
	dohMap := make(map[string]string)
	for _, addr := range upstream.Primary {
		if strings.HasPrefix("https", addr) {
			uri, ip, found := strings.Cut(addr, "#")
			if !found {
				continue
			}
			parsedUri, err := url.Parse(uri)
			if err != nil {
				continue
			}
			dohMap[parsedUri.Host+":443"] = ip
		}
	}
	server := &Server{
		Mux:       dns.NewServeMux(),
		client:    NewDNSClient(dohMap),
		domain:    domain,
		upstream:  upstream,
		sometimes: rate.NewLimiter(rate.Every(1*time.Second), 1), // at most once per second
		hostname:  hostname,
		ip:        ip,
		subnames:  make(map[lcHostname]map[string]net.IP),
	}
	server.prom.registry = prometheus.NewRegistry()

	server.prom.queries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_queries",
		Help: "Number of DNS queries received",
	})
	server.prom.registry.MustRegister(server.prom.queries)

	server.prom.upstream = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_upstream",
			Help: "Which upstream answered which DNS query",
		},
		[]string{"upstream"},
	)
	server.prom.registry.MustRegister(server.prom.upstream)

	server.prom.questions = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "dns_questions",
		Help:    "Number of questions in each DNS request",
		Buckets: prometheus.LinearBuckets(0, 1, 10),
	})
	server.prom.registry.MustRegister(server.prom.questions)

	server.prom.registry.MustRegister(collectors.NewGoCollector())
	server.initHostsLocked()
	server.Mux.HandleFunc(".", server.handleRequest)
	server.Mux.HandleFunc("lan.", server.handleInternal)
	server.Mux.HandleFunc("localhost.", server.handleInternal)
	go func() {
		for range time.Tick(10 * time.Second) {
			server.probeUpstreamLatency()
		}
	}()
	return server
}

func (s *Server) initHostsLocked() {
	s.hostsByName = make(map[lcHostname]string)
	s.hostsByIP = make(map[string]string)
	if s.hostname != "" && s.ip != "" {
		lower := strings.ToLower(s.hostname)
		s.hostsByName[lcHostname(lower)] = s.ip
		if rev, err := dns.ReverseAddr(s.ip); err == nil {
			s.hostsByIP[rev] = s.hostname
		}
		s.Mux.HandleFunc(lower+".", s.subnameHandler(s.hostname))
		s.Mux.HandleFunc(lower+"."+s.domain+".", s.subnameHandler(s.hostname))
	}
}

type measurement struct {
	upstream string
	rtt      time.Duration
}

func (m measurement) String() string {
	return fmt.Sprintf("{upstream: %s, rtt: %v}", m.upstream, m.rtt)
}

func (s *Server) probe(wg *sync.WaitGroup, upstreams []string, results []measurement) {
	for idx, u := range upstreams {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			// resolve a most-definitely cached record
			m := new(dns.Msg)
			m.SetQuestion("google.ch.", dns.TypeA)
			start := time.Now()
			_, _, err := s.client.Exchange(m, u, nil)
			rtt := time.Since(start)
			if err != nil {
				// including unresponsive upstreams in results makes the update
				// code simpler:
				results[idx] = measurement{u, time.Duration(math.MaxInt64)}
				return
			}
			results[idx] = measurement{u, rtt}
		}(idx, u)
	}
}

func (s *Server) probeUpstreamLatency() {
	upstreams := s.upstreams()
	primaryResults := make([]measurement, len(upstreams.Primary))
	secondaryResults := make([]measurement, len(upstreams.Secondary))
	var wg sync.WaitGroup
	s.probe(&wg, upstreams.Primary, primaryResults)
	s.probe(&wg, upstreams.Secondary, secondaryResults)
	wg.Wait()
	// Re-order by resolving latency:
	sort.Slice(primaryResults, func(i, j int) bool {
		return primaryResults[i].rtt < primaryResults[j].rtt
	})
	sort.Slice(secondaryResults, func(i, j int) bool {
		return secondaryResults[i].rtt < secondaryResults[j].rtt
	})
	log.Printf("probe results: %v", append(primaryResults, secondaryResults...))
	for idx, result := range primaryResults {
		upstreams.Primary[idx] = result.upstream
	}
	for idx, result := range secondaryResults {
		upstreams.Secondary[idx] = result.upstream
	}
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()
	s.upstream = upstreams
}

func (s *Server) hostByName(n string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hostsByName[lcHostname(strings.ToLower(n))]
	return r, ok
}

func (s *Server) hostByIP(n string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hostsByIP[n]
	return r, ok
}

func (s *Server) subname(hostname, host string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.subnames[lcHostname(strings.ToLower(hostname))][host]
	return r, ok
}

func (s *Server) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(s.prom.registry, promhttp.HandlerOpts{})
}

func (s *Server) DyndnsHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	ip := net.ParseIP(r.FormValue("ip"))
	if ip == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("net.SplitHostPort(%q): %v", r.RemoteAddr, err), http.StatusBadRequest)
		return
	}
	rev, err := dns.ReverseAddr(remote)
	if err != nil {
		http.Error(w, fmt.Sprintf("dns.ReverseAddr(%v): %v", remote, err), http.StatusBadRequest)
		return
	}
	hostname, ok := s.hostsByIP[rev]
	if !ok {
		err := fmt.Sprintf("connection without corresponding DHCP lease: %v", rev)
		http.Error(w, err, http.StatusForbidden)
		return
	}
	lower := strings.ToLower(hostname)
	log.Printf("%s requesting dns %v -> %v", lower, host, ip)
	subnames, ok := s.subnames[lcHostname(lower)]
	if !ok {
		subnames = make(map[string]net.IP)
		s.subnames[lcHostname(lower)] = subnames
	}
	subnames[host] = ip
	w.Write([]byte("ok\n"))
}

func (s *Server) SetLeases(leases []dhcp4d.Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initHostsLocked()
	now := time.Now()
	{
		// defensive copy
		slice := make([]dhcp4d.Lease, len(leases))
		copy(slice, leases)
		leases = slice
	}
	// First entry wins, so we order by expiration descendingly to put the
	// newest entry for any given name into s.hostsByName.
	sort.Slice(leases, func(i, j int) bool {
		return !leases[i].Expiry.Before(leases[j].Expiry)
	})
	for _, l := range leases {
		if l.Expired(now) {
			continue
		}
		if l.Hostname == "" {
			continue
		}
		lower := strings.ToLower(l.Hostname)
		if _, ok := s.hostsByName[lcHostname(lower)]; ok {
			continue // don’t overwrite e.g. the hostname entry
		}
		s.hostsByName[lcHostname(lower)] = l.Addr.String()
		if rev, err := dns.ReverseAddr(l.Addr.String()); err == nil {
			s.hostsByIP[rev] = l.Hostname
		}
		s.Mux.HandleFunc(lower+".", s.subnameHandler(lower))
		s.Mux.HandleFunc(lower+"."+s.domain+".", s.subnameHandler(lower))
	}
}

var (
	localNets = []*net.IPNet{
		// loopback: https://tools.ietf.org/html/rfc3330#section-2
		diag.MustParseCIDR("127.0.0.0/8"),
		// loopback: https://tools.ietf.org/html/rfc3513#section-2.4
		diag.MustParseCIDR("::1/128"),

		// reversed: https://tools.ietf.org/html/rfc1918#section-3
		diag.MustParseCIDR("10.0.0.0/8"),
		diag.MustParseCIDR("172.16.0.0/12"),
		diag.MustParseCIDR("192.168.0.0/16"),
	}
)

func reverse(ss []string) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

func isLocalInAddrArpa(q string) bool {
	if !strings.HasSuffix(q, ".in-addr.arpa.") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(q, ".in-addr.arpa."), ".")
	reverse(parts)
	ip := net.ParseIP(strings.Join(parts, "."))
	if ip == nil {
		return false
	}
	var local bool
	for _, l := range localNets {
		if l.Contains(ip) {
			local = true
			break
		}
	}
	return local
}

var errEmpty = errors.New("no answers")

func (s *Server) resolve(q dns.Question) (rr dns.RR, err error) {
	if q.Qclass != dns.ClassINET {
		return nil, nil
	}
	if strings.ToLower(q.Name) == "localhost." {
		if q.Qtype == dns.TypeAAAA {
			return dns.NewRR(q.Name + " 3600 IN AAAA ::1")
		}
		if q.Qtype == dns.TypeA {
			return dns.NewRR(q.Name + " 3600 IN A 127.0.0.1")
		}
	}
	if q.Qtype == dns.TypeA ||
		q.Qtype == dns.TypeAAAA ||
		q.Qtype == dns.TypeMX {
		name := strings.TrimSuffix(q.Name, ".")
		name = strings.TrimSuffix(name, "."+s.domain)
		if host, ok := s.hostByName(name); ok {
			if q.Qtype == dns.TypeA {
				return dns.NewRR(q.Name + " 3600 IN A " + host)
			}
			return nil, errEmpty
		}
	}
	if q.Qtype == dns.TypePTR {
		if host, ok := s.hostByIP(q.Name); ok {
			return dns.NewRR(q.Name + " 3600 IN PTR " + host + "." + s.domain)
		}
		if strings.HasSuffix(q.Name, "127.in-addr.arpa.") {
			return dns.NewRR(q.Name + " 3600 IN PTR localhost.")
		}
	}
	return nil, nil
}

func (s *Server) handleInternal(w dns.ResponseWriter, r *dns.Msg) {
	s.prom.queries.Inc()
	s.prom.questions.Observe(float64(len(r.Question)))
	s.prom.upstream.WithLabelValues("local").Inc()
	if len(r.Question) != 1 { // TODO: answer all questions we can answer
		return
	}
	rr, err := s.resolve(r.Question[0])
	if err != nil {
		if err == errEmpty {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			w.WriteMsg(m)
			return
		}
		log.Fatal(err)
	}
	if rr != nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		m.Answer = append(m.Answer, rr)
		w.WriteMsg(m)
		return
	}
	// Send an authoritative NXDOMAIN for local names:
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.SetRcode(r, dns.RcodeNameError)
	w.WriteMsg(m)
}

func (s *Server) upstreams() Upstreams {
	s.upstreamMu.RLock()
	defer s.upstreamMu.RUnlock()
	result := Upstreams{}
	result.Primary = make([]string, len(s.upstream.Primary))
	result.Secondary = make([]string, len(s.upstream.Secondary))
	copy(result.Primary, s.upstream.Primary)
	copy(result.Secondary, s.upstream.Secondary)
	return result
}

func (s *Server) updateUpstreams(u string) {
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()
	if idx := slices.Index(s.upstream.Primary, u); idx > 0 {
		s.upstream.Primary = append(append([]string{u}, s.upstream.Primary[:idx]...), s.upstream.Primary[idx+1:]...)
		return
	}
	if idx := slices.Index(s.upstream.Secondary, u); idx > 0 {
		s.upstream.Secondary = append(append([]string{u}, s.upstream.Secondary[:idx]...), s.upstream.Secondary[idx+1:]...)
		return
	}
}

func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 1 { // TODO: answer all questions we can answer
		q := r.Question[0]
		if q.Qtype == dns.TypePTR && q.Qclass == dns.ClassINET && isLocalInAddrArpa(q.Name) {
			s.handleInternal(w, r)
			return
		}
	}

	s.prom.queries.Inc()
	s.prom.questions.Observe(float64(len(r.Question)))
	s.prom.upstream.WithLabelValues("DNS").Inc()
	var (
		err        error
		clientInfo = make(map[string]string) // device_id=12345&device_name=John's%20Firefox&device_model=iPhone
		// TODO: make device_id and make it compatible with headscale.
		// TODO: extract device_model from dhcp vendor identifier
	)
	if addr := w.RemoteAddr(); addr != nil {
		if ip, _, ok := strings.Cut(w.RemoteAddr().String(), ":"); ok {
			ip, _ = dns.ReverseAddr(ip)
			host, ok := s.hostByIP(ip)
			if ok {
				clientInfo["device_name"] = host
			}
		}
	}
	upstreams := s.upstreams()
	// We have primary and secondar so we can ensure that nextdns doh is tried first
	for idx, u := range append(upstreams.Primary, upstreams.Secondary...) {
		var in *dns.Msg
		in, _, err = s.client.Exchange(r, u, clientInfo)
		if err != nil {
			if s.sometimes.Allow() {
				log.Printf("resolving %v failed: %v", r.Question, err)
			}
			continue // fall back to next-slower upstream
		}
		w.WriteMsg(in)
		if idx > 0 {
			s.updateUpstreams(u)
		}
		return
	}
	// DNS has no reply for resolving errors
}

func (s *Server) resolveSubname(hostname string, q dns.Question) (dns.RR, error) {
	if q.Qclass != dns.ClassINET {
		return nil, nil
	}
	if q.Qtype == dns.TypeA ||
		q.Qtype == dns.TypeAAAA ||
		q.Qtype == dns.TypeMX {
		name := strings.TrimSuffix(q.Name, "."+hostname+".")
		name = strings.TrimSuffix(name, "."+hostname+"."+s.domain+".")

		if lower := strings.ToLower(q.Name); lower == hostname+"." ||
			lower == hostname+"."+s.domain+"." {
			host, ok := s.hostByName(hostname)
			if !ok {
				// The corresponding DHCP lease might have expired, but this
				// handler is still installed on the mux.
				return nil, nil // NXDOMAIN
			}
			if q.Qtype == dns.TypeA {
				return dns.NewRR(q.Name + " 3600 IN A " + host)
			}
			return nil, errEmpty
		}

		if ip, ok := s.subname(hostname, name); ok {
			if q.Qtype == dns.TypeA && ip.To4() != nil {
				return dns.NewRR(q.Name + " 3600 IN A " + ip.String())
			}
			if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
				return dns.NewRR(q.Name + " 3600 IN AAAA " + ip.String())
			}
			return nil, errEmpty
		}
	}
	return nil, nil
}

func (s *Server) subnameHandler(hostname string) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) != 1 { // TODO: answer all questions we can answer
			return
		}

		rr, err := s.resolveSubname(hostname, r.Question[0])
		if err != nil {
			if err == errEmpty {
				m := new(dns.Msg)
				m.SetReply(r)
				m.RecursionAvailable = true
				w.WriteMsg(m)
				return
			}
			log.Fatalf("question %#v: %v", r.Question[0], err)
		}
		if rr != nil {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			m.Answer = append(m.Answer, rr)
			w.WriteMsg(m)
			return
		}
		// Send an authoritative NXDOMAIN for local names:
		m := new(dns.Msg)
		m.RecursionAvailable = true
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	}
}
