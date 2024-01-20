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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rtr7/router7/internal/dhcp4d"
	"github.com/rtr7/router7/internal/teelogger"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

var log = teelogger.NewConsole()

// lcHostname is a string type used for lower-cased hostnames so that the
// DHCP-based local name resolution can be made case-insensitive.
type lcHostname string

type IP struct {
	IPv6 net.IP     `json:"ipv6"`
	IPv4 net.IP     `json:"ipv4"`
	Host lcHostname `json:"host"` // lease that the IPs are updated from. If no lease exists for this host it is never updated.
}

type Server struct {
	Mux       *dns.ServeMux
	once      bool
	client    *dns.Client
	domain    lcHostname
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
	subnames     map[lcHostname]map[lcHostname]IP // hostname → subname → ip

	upstreamMu sync.RWMutex
	upstream   []string
}

func (lh *lcHostname) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*lh = lcHostname(strings.ToLower(s))
	return nil
}

func NewServer(addr, domain string) *Server {
	hostname, _ := os.Hostname()
	ip, _, _ := net.SplitHostPort(addr)
	server := &Server{
		Mux:    dns.NewServeMux(),
		client: &dns.Client{},
		domain: lcHostname(strings.ToLower(domain)),
		upstream: []string{
			// https://developers.google.com/speed/public-dns/docs/using#google_public_dns_ip_addresses
			"1.1.1.1:53",
			"1.0.0.1:53",
			"[2606:4700:4700::1111]:53",
			"[2606:4700:4700::1001]:53",
			"8.8.8.8:53",
			"8.8.4.4:53",
			"[2001:4860:4860::8888]:53",
			"[2001:4860:4860::8844]:53",
		},
		sometimes: rate.NewLimiter(rate.Every(1*time.Second), 1), // at most once per second
		hostname:  hostname,
		ip:        ip,
		subnames:  make(map[lcHostname]map[lcHostname]IP),
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

	server.prom.registry.MustRegister(prometheus.NewGoCollector())
	server.initHostsLocked()
	server.Mux.HandleFunc(".", server.handleRequest)
	server.Mux.HandleFunc(strings.ToLower(domain)+".", server.subnameHandler(server.domain))
	server.Mux.HandleFunc("lan.", server.subnameHandler(server.domain))
	server.Mux.HandleFunc("localhost.", server.handleInternal)
	go func() {
		for range time.Tick(10 * time.Second) {
			server.probeUpstreamLatency()
		}
	}()
	return server
}

func (s *Server) initHostsLocked() {
	for k := range s.subnames {
		if k != s.domain {
			s.Mux.HandleRemove(string(k))
		}
	}
	s.hostsByName = make(map[lcHostname]string)
	s.hostsByIP = make(map[string]string)
	s.subnames[s.domain] = make(map[lcHostname]IP)
	if s.hostname != "" && s.ip != "" {
		lower := lcHostname(strings.ToLower(s.hostname))
		s.hostsByName[lower] = s.ip
		if rev, err := dns.ReverseAddr(s.ip); err == nil {
			s.hostsByIP[rev] = s.hostname
		}
		subnames := s.subnames[s.domain]
		ip := net.ParseIP(s.ip)
		if ip.To4() != nil {
			subnames[lower] = IP{IPv4: ip}
		} else {
			subnames[lower] = IP{IPv6: ip}
		}
	}
}

type measurement struct {
	upstream string
	rtt      time.Duration
}

func (m measurement) String() string {
	return fmt.Sprintf("{upstream: %s, rtt: %v}", m.upstream, m.rtt)
}

func (s *Server) probeUpstreamLatency() {
	upstreams := s.upstreams()
	results := make([]measurement, len(upstreams))
	var wg sync.WaitGroup
	for idx, u := range upstreams {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			// resolve a most-definitely cached record
			m := new(dns.Msg)
			m.SetQuestion("google.ch.", dns.TypeA)
			start := time.Now()
			_, _, err := s.client.Exchange(m, u)
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
	wg.Wait()
	// Re-order by resolving latency:
	sort.Slice(results, func(i, j int) bool {
		return results[i].rtt < results[j].rtt
	})
	log.Printf("probe results: %v", results)
	for idx, result := range results {
		upstreams[idx] = result.upstream
	}
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()
	s.upstream = upstreams
}

func (s *Server) hostByName(n lcHostname) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hostsByName[n]
	return r, ok
}

func (s *Server) hostByIP(n string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hostsByIP[n]
	return r, ok
}

func (s *Server) subname(domain, host string) (IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.subnames[lcHostname(strings.ToLower(domain))][lcHostname(strings.ToLower(host))]
	return r, ok
}

func (s *Server) setSubname(ip IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hdnSlice := strings.SplitN(string(ip.Host), ".", 2)
	host := lcHostname(hdnSlice[0])
	domain := lcHostname("")
	if len(hdnSlice) == 2 {
		domain = lcHostname(hdnSlice[1])
	}
	if domain == "" {
		domain = s.domain
	}
	subnames, ok := s.subnames[domain]
	if !ok {
		subnames = make(map[lcHostname]IP)
		s.subnames[domain] = subnames
	}
	curIP, ok := subnames[host]
	if !ok {
		subnames[host] = ip
	} else {
		// refuse to overwrite a lease
		if _, ok := s.hostsByName[ip.Host]; ok {
			if curIP.IPv4 == nil {
				curIP.IPv4 = ip.IPv4
			}
			if curIP.IPv6 == nil {
				curIP.IPv6 = ip.IPv6
			}
			subnames[host] = curIP
		} else {
			subnames[host] = ip
		}
	}
}

func (s *Server) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(s.prom.registry, promhttp.HandlerOpts{})
}

func (s *Server) DyndnsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		hostname lcHostname // with domain
		hostlan  string     // with lan domain
	)
	host := strings.Trim(r.FormValue("host"), ". ")
	ip := net.ParseIP(r.FormValue("ip"))
	if ip == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}

	// s.mu.Lock()
	// defer s.mu.Unlock()
	/*
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
	*/
	if strings.HasSuffix(host, "localhost") {
		http.Error(w, fmt.Sprintf("invalid localhost not allowed: %v", host), http.StatusBadRequest)
		return
	}
	hostname = lcHostname(strings.ToLower(host))
	if strings.HasSuffix(string(hostname), ".lan") { // change lan to domain
		hostname = lcHostname(strings.TrimSuffix(string(hostname), "lan")) + s.domain
	} else if !strings.HasSuffix(string(hostname), "."+string(s.domain)) { // add domain if not already there
		hostname += "." + s.domain
	}

	hostlan = strings.TrimSuffix(string(hostname), string(s.domain)) + "lan"

	ipr := IP{
		Host: hostname,
	}
	if ip.To4() == nil {
		ipr.IPv6 = ip
	} else {
		ipr.IPv4 = ip
	}
	s.setSubname(ipr)
	if strings.Contains(strings.TrimSuffix(string(ipr.Host), "."+string(s.domain)), ".") { // strip domain if it still has a "." it is a subname
		hdnSlice := strings.SplitN(string(ipr.Host), ".", 2)
		domain := lcHostname(hdnSlice[1]) // guaranteed by if statement

		s.Mux.HandleFunc(strings.ToLower(host), s.subnameHandler(domain)) // from post
		s.Mux.HandleFunc(string(hostname), s.subnameHandler(domain))      // with domain
		s.Mux.HandleFunc(hostlan, s.subnameHandler(domain))               // with "lan" domain
	}
	w.Write([]byte("ok\n"))
}

func (s *Server) SetDNSEntries(dnsEntries []IP) {
	for _, entry := range dnsEntries {
		dn := string(entry.Host)
		if strings.HasSuffix(dn, ".lan") {
			entry.Host = lcHostname(strings.TrimSuffix(dn, "lan")) + s.domain
		}
		s.setSubname(entry)
		hdnSlice := strings.SplitN(string(entry.Host), ".", 2)
		domain := lcHostname("")
		if len(hdnSlice) == 2 {
			domain = lcHostname(hdnSlice[1])
		}
		if domain == "" || domain == s.domain {
			continue
		}
		s.Mux.HandleFunc(string(domain), s.subnameHandler(domain))
	}
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
		lower := lcHostname(strings.ToLower(l.Hostname))
		if _, ok := s.hostsByName[lower]; ok {
			continue // don’t overwrite e.g. the hostname entry
		}
		s.hostsByName[lower] = l.Addr.String()

		subnames, ok := s.subnames[s.domain]
		if !ok {
			subnames = make(map[lcHostname]IP)
			s.subnames[s.domain] = subnames
		}
		if l.Addr.To4() != nil {
			subnames[lower] = IP{
				IPv4: l.Addr,
				IPv6: subnames[lower].IPv6,
			}
		} else {
			subnames[lower] = IP{
				IPv4: subnames[lower].IPv4,
				IPv6: l.Addr,
			}
		}

		if rev, err := dns.ReverseAddr(l.Addr.String()); err == nil {
			s.hostsByIP[rev] = l.Hostname
		}
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

var (
	localNets = []*net.IPNet{
		// loopback: https://tools.ietf.org/html/rfc3330#section-2
		mustParseCIDR("127.0.0.0/8"),
		// loopback: https://tools.ietf.org/html/rfc3513#section-2.4
		mustParseCIDR("::1/128"),

		// reversed: https://tools.ietf.org/html/rfc1918#section-3
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("172.16.0.0/12"),
		mustParseCIDR("192.168.0.0/16"),
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

func (s *Server) resolveLocal(q dns.Question) (rr dns.RR, err error) {
	if strings.ToLower(q.Name) == "localhost." {
		if q.Qtype == dns.TypeAAAA {
			return dns.NewRR(q.Name + " 3600 IN AAAA ::1")
		}
		if q.Qtype == dns.TypeA {
			return dns.NewRR(q.Name + " 3600 IN A 127.0.0.1")
		}
	}
	if q.Qtype == dns.TypePTR {
		if host, ok := s.hostByIP(q.Name); ok {
			return dns.NewRR(q.Name + " 3600 IN PTR " + host + "." + string(s.domain))
		}
		if strings.HasSuffix(q.Name, "127.in-addr.arpa.") {
			return dns.NewRR(q.Name + " 3600 IN PTR localhost.")
		}
	}
	return nil, nil
}

func (s *Server) handleInternal(w dns.ResponseWriter, r *dns.Msg) {
	s.promInc("local", r)
	if len(r.Question) != 1 { // TODO: answer all questions we can answer
		return
	}
	rr, err := s.resolveLocal(r.Question[0])
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
	// Send an authoritative NXDOMAIN for local:
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.SetRcode(r, dns.RcodeNameError)
	w.WriteMsg(m)
}

func (s *Server) upstreams() []string {
	s.upstreamMu.RLock()
	defer s.upstreamMu.RUnlock()
	result := make([]string, len(s.upstream))
	copy(result, s.upstream)
	return result
}

func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 1 { // TODO: answer all questions we can answer
		q := r.Question[0]
		if q.Qtype == dns.TypePTR && q.Qclass == dns.ClassINET && isLocalInAddrArpa(q.Name) {
			s.handleInternal(w, r)
			return
		}
	}
	if !strings.Contains(strings.TrimSuffix(r.Question[0].Name, "."), ".") {
		s.subnameHandler(s.domain)(w, r)
		return
	}

	s.promInc("DNS", r)

	if r.RecursionDesired {
		for idx, u := range s.upstreams() {
			in, _, err := s.client.Exchange(r, u)
			if err != nil {
				if s.sometimes.Allow() {
					log.Printf("resolving %v failed: %v", r.Question, err)
				}
				continue // fall back to next-slower upstream
			}
			if len(in.Answer) > 1 {
				if in.Answer[0].Header().Rrtype == dns.TypeCNAME {
					for i, rr := range in.Answer {
						if rr != nil && rr.Header() != nil && rr.Header().Rrtype == dns.TypeA {
							newRR, err := s.resolveSubname(string(s.domain), dns.Question{strings.ToLower(rr.Header().Name), dns.TypeA, dns.ClassINET})
							if err == nil && newRR != nil {
								in.Answer[i] = newRR
							}
						}
					}
				}
			}
			w.WriteMsg(in)
			if idx > 0 {
				// re-order this upstream to the front of s.upstream.
				s.upstreamMu.Lock()
				// if the upstreams were reordered in the meantime leave them alone
				if s.upstream[idx] == u {
					s.upstream = append(append([]string{u}, s.upstream[:idx]...), s.upstream[idx+1:]...)
				}
				s.upstreamMu.Unlock()
			}
			return
		}
	} else {
		for _, u := range s.upstreams() {
			nr := r.Copy()
			nr.Question[0].Qtype = dns.TypeSOA
			nr.RecursionDesired = true
			soa, _, err := s.client.Exchange(nr, u)
			fmt.Println(err, soa)
			fmt.Println()
			fmt.Println(soa.Ns)

			if len(soa.Ns) > 0 {
				soa2 := soa.Ns[0].(*dns.SOA)
				in, _, err := s.client.Exchange(r, strings.TrimRight(soa2.Ns, ".")+":53")
				fmt.Println(err, in)
				if err != nil {
					if s.sometimes.Allow() {
						log.Printf("resolving %v failed: %v", r.Question, err)
					}
					continue // fall back to next-slower upstream
				}
				w.WriteMsg(in)
				return
			}
		}
	}
	// DNS has no reply for resolving errors
}

func (s *Server) getSubname(domain string, queryName string) (IP,bool) {
	name := strings.TrimSuffix(queryName, ".")
	name = strings.TrimSuffix(name, ".lan")                                               // trim lan domain
	name = strings.TrimSuffix(name, "."+string(s.domain))                                 // trim server domain
	name = strings.TrimSuffix(name, "."+strings.TrimSuffix(domain, "."+string(s.domain))) // trim function domain
	if ip, ok := s.subname(domain, name); ok {
		return ip, true
	}
	return IP{},false
}

func (s *Server) resolveSubname(domain string, q dns.Question) (dns.RR, error) {
	if q.Qclass != dns.ClassINET {
		return nil, nil
	}
	ip,ok := s.getSubname(domain,q.Name)
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA /*|| q.Qtype == dns.TypeMX*/ {
		if ok {
			if q.Qtype == dns.TypeA && ip.IPv4.To4() != nil {
				return dns.NewRR(q.Name + " 3600 IN A " + ip.IPv4.String())
			}
			if q.Qtype == dns.TypeAAAA && ip.IPv6.To4() == nil && ip.IPv6 != nil {
				return dns.NewRR(q.Name + " 3600 IN AAAA " + ip.IPv6.String())
			}
			return nil, errEmpty
		}
	}
	return nil, nil
}

func (s *Server) promInc(label string, r *dns.Msg) {
	s.prom.queries.Inc()
	s.prom.questions.Observe(float64(len(r.Question)))
	s.prom.upstream.WithLabelValues(label).Inc()
}

func (s *Server) subnameHandler(domain lcHostname) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) != 1 { // TODO: answer all questions we can answer
			s.promInc("local", r)
			return
		}
		rr, err := s.resolveSubname(string(domain), r.Question[0])

		if err != nil {
			s.promInc("local", r)
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
			s.promInc("local", r)
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			m.Answer = append(m.Answer, rr)
			w.WriteMsg(m)
			return
		}

		// Send an authoritative NXDOMAIN for local names:
		if _,ok := s.getSubname(string(domain),r.Question[0].Name);r.Question[0].Qtype == dns.TypePTR || (r.Question[0].Qtype == dns.TypeCNAME && ok) || !strings.Contains(strings.TrimSuffix(r.Question[0].Name, "."), ".") || strings.HasSuffix(r.Question[0].Name, ".lan.") {
			s.promInc("local", r)
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}

		s.handleRequest(w, r)
	}
}
