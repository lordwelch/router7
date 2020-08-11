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

// Binary dnsd answers DNS requests by forwarding or consulting DHCP leases.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/gokrazy/gokrazy"
	miekgdns "github.com/miekg/dns"

	"github.com/rtr7/router7/internal/dhcp4d"
	"github.com/rtr7/router7/internal/dns"
	"github.com/rtr7/router7/internal/multilisten"
	"github.com/rtr7/router7/internal/netconfig"

	_ "net/http/pprof"
)

var (
	httpListeners = multilisten.NewPool()
	dnsListeners  = multilisten.NewPool()

	perm   = flag.String("perm", "/perm", "path to replace /perm")
	domain = flag.String("domain", "lan", "domain name for your network")
)

func updateListeners(mux *miekgdns.ServeMux) error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}

	dnsListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &listenerAdapter{&miekgdns.Server{
			Addr:    net.JoinHostPort(host, "53"),
			Net:     "udp",
			Handler: mux,
		}}
	})

	if net1, err := multilisten.IPv6Net1(*perm); err == nil {
		hosts = append(hosts, net1)
	}

	httpListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &http.Server{Addr: net.JoinHostPort(host, "8053")}
	})

	return nil
}

type listenerAdapter struct {
	*miekgdns.Server
}

func (a *listenerAdapter) Close() error { return a.Shutdown() }

func logic() error {
	// TODO: set correct upstream DNS resolver(s)
	ip, err := netconfig.LinkAddress(*perm, "lan0")
	if err != nil {
		return err
	}
	srv := dns.NewServer(ip.String()+":53", *domain)
	readLeases := func() error {
		b, err := ioutil.ReadFile(path.Join(*perm, "/dhcp4d/leases.json"))
		if err != nil {
			return err
		}
		var leases []dhcp4d.Lease
		if err := json.Unmarshal(b, &leases); err != nil {
			return err
		}
		srv.SetLeases(leases)
		return nil
	}
	if err := readLeases(); err != nil {
		log.Printf("cannot resolve DHCP hostnames: %v", err)
	}
	http.Handle("/metrics", srv.PrometheusHandler())
	http.HandleFunc("/dyndns", srv.DyndnsHandler)
	if err := updateListeners(srv.Mux); err != nil {
		return err
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for range ch {
		if err := updateListeners(srv.Mux); err != nil {
			log.Printf("updateListeners: %v", err)
		}
		if err := readLeases(); err != nil {
			log.Printf("readLeases: %v", err)
		}
	}
	return nil
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
