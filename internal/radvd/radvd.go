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

// Package radvd implements IPv6 router advertisments.
package radvd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/rtr7/router7/internal/dhcp4d"
	"github.com/rtr7/router7/internal/diag"
	"github.com/rtr7/router7/internal/notify"

	"golang.org/x/net/ipv6"
)

type Server struct {
	pc     *ipv6.PacketConn
	ifname string

	mu       sync.Mutex
	prefixes []net.IPNet
	iface    *net.Interface

	knownAddresses map[string]dhcp4d.Lease
}

func NewServer() (*Server, error) {
	return &Server{
		knownAddresses: make(map[string]dhcp4d.Lease),
	}, nil
}
func getLeases() (map[string]string, error) {
	f, err := os.Open("/perm/dhcp4d/leases.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	jd := json.NewDecoder(f)

	var leases []dhcp4d.Lease
	if err := jd.Decode(&leases); err != nil {
		return nil, err
	}
	// Map MAC Addresses to hostnames for ipv6
	byMac := make(map[string]string, len(leases))
	for _, lease := range leases {
		byMac[lease.HardwareAddr] = lease.Hostname
	}
	return byMac, nil
}

func (s *Server) UpdateDNS(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	leases, err := getLeases()
	if err == nil {
		for _, address := range s.knownAddresses {
			if address.Hostname != "" {
				continue
			}
			address.Hostname = leases[address.HardwareAddr]
		}
	}
	m, err := ndp.ParseMessage(b)
	if err != nil {
		return err
	}
	if m.Type() != ipv6.ICMPTypeNeighborAdvertisement {
		return fmt.Errorf("incorrect icmp message recieved expected %s, got %s", ipv6.ICMPTypeNeighborAdvertisement, m.Type())
	}
	n := m.(*ndp.NeighborAdvertisement)
	var hw net.HardwareAddr
	for _, o := range n.Options {
		if o.Code() == uint8(ndp.Target) {
			ll := o.(*ndp.LinkLayerAddress)
			hw = ll.Addr
			break
		}
	}
	if hw == nil {
		// Ignore advertisements that donot provide the MAC
		log.Printf("Ignoring advertisement(no mac): %v", n)
		return nil
	}
	if !n.Solicited {
		// Ignore advertisements that are not solicited
		log.Printf("Ignoring advertisement(is not solicited): %v", n)
		return nil
	}
	if _, ok := leases[hw.String()]; !ok {
		log.Println("Ignoring advertisement(no dhcp4 lease for mac):", n)
		return nil
	}
	log.Printf("Found IPv6 address %s for MAC address %s (%s)", n.TargetAddress, hw, leases[hw.String()])
	s.knownAddresses[hw.String()] = dhcp4d.Lease{
		Addr:         net.IP(n.TargetAddress.AsSlice()),
		HardwareAddr: hw.String(),
		LastACK:      time.Now(),
		Expiry:       time.Now().Add(10 * time.Minute),
		Hostname:     leases[hw.String()],
	}
	addresses := make([]dhcp4d.Lease, 0, len(s.knownAddresses))
	for _, lease := range s.knownAddresses {
		addresses = append(addresses, lease)
	}
	buf := &bytes.Buffer{}
	j := json.NewEncoder(buf)
	j.SetIndent("", "  ")
	err = j.Encode(addresses)
	if err != nil {
		return err
	}
	err = os.WriteFile("/perm/radvd.addresses.json", buf.Bytes(), 0o600)
	if err != nil {
		return err
	}
	if err := notify.Process("/user/dnsd", syscall.SIGUSR1); err != nil {
		log.Printf("notifying dnsd: %v", err)
	}
	return nil
}

func (s *Server) SetPrefixes(prefixes []net.IPNet) {
	s.mu.Lock()
	if s.ifname != "" {
		var err error
		// Gather details about the interface again, the MAC address might have been
		// changed.
		s.iface, err = net.InterfaceByName(s.ifname)
		if err != nil {
			log.Fatal(err) // interface vanished
		}
	}
	s.prefixes = prefixes
	s.mu.Unlock()
	if s.iface != nil {
		s.sendAdvertisement(nil)
	}
}

func (s *Server) Serve(ifname string, conn net.PacketConn) error {
	var err error
	s.ifname = ifname
	s.iface, err = net.InterfaceByName(ifname)
	if err != nil {
		return err
	}

	defer conn.Close()
	s.pc = ipv6.NewPacketConn(conn)
	s.pc.SetHopLimit(255)          // as per RFC 4861, section 4.1
	s.pc.SetMulticastHopLimit(255) // as per RFC 4861, section 4.1

	var filter ipv6.ICMPFilter
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterSolicitation)
	filter.Accept(ipv6.ICMPTypeNeighborAdvertisement)
	if err := s.pc.SetICMPFilter(&filter); err != nil {
		return err
	}

	go func() {
		for {
			s.sendAdvertisement(nil) // TODO: handle error
			time.Sleep(1 * time.Minute)
		}
	}()

	// A 512 bytes buffer is sufficient for router solicitation packets, which
	// are basically empty.
	buf := make([]byte, 512)
	for {
		n, _, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if ipv6.ICMPType(buf[0]) == ipv6.ICMPTypeNeighborAdvertisement {
			err = s.UpdateDNS(buf[:n])
			if err != nil {
				log.Printf("Failed to update dns %v %#v", err, buf[:n])
			}
			continue
		}
		if !strings.HasSuffix(addr.String(), "%"+ifname) {
			log.Println("ignoring off-interface request from", addr.String())
			continue
		}
		// TODO: isn’t this guaranteed by the filter above?
		if n == 0 || ipv6.ICMPType(buf[0]) != ipv6.ICMPTypeRouterSolicitation {
			continue
		}
		if err := s.sendAdvertisement(addr); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) ListenAndServe(ifname string) error {
	// TODO(correctness): would it be better to listen on
	// net.IPv6linklocalallrouters? Just specifying that results in an error,
	// though.
	conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{net.IPv6unspecified, ""})
	if err != nil {
		return err
	}
	return s.Serve(ifname, conn)
}

var ipv6LinkLocal = diag.MustParseCIDR("fe80::/10")

func (s *Server) sendAdvertisement(addr net.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prefixes == nil {
		return nil // nothing to do
	}
	if addr == nil {
		addr = &net.IPAddr{
			IP:   net.IPv6linklocalallnodes,
			Zone: s.iface.Name,
		}
	}

	var options []ndp.Option

	if len(s.prefixes) > 0 {
		addrs, err := s.iface.Addrs()
		if err != nil {
			return err
		}
		var linkLocal netip.Addr
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipv6LinkLocal.Contains(ipnet.IP) {
				linkLocal, _ = netip.AddrFromSlice(ipnet.IP)
				break
			}
		}
		if linkLocal.IsValid() && !linkLocal.IsUnspecified() {
			options = append(options, &ndp.RecursiveDNSServer{
				Lifetime: 30 * time.Minute,
				Servers:  []netip.Addr{linkLocal},
			})
		}
	}

	for _, prefix := range s.prefixes {
		ones, _ := prefix.Mask.Size()
		// Use the first /64 subnet within larger prefixes
		if ones < 64 {
			ones = 64
		}

		addr, _ := netip.AddrFromSlice(prefix.IP)
		options = append(options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(ones),
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  2 * time.Hour,
			PreferredLifetime:              30 * time.Minute,
			Prefix:                         addr,
		})
	}

	options = append(options,
		&ndp.DNSSearchList{
			// TODO: audit all lifetimes and express them in relation to each other
			Lifetime: 20 * time.Minute,
			// TODO: single source of truth for search domain name
			DomainNames: []string{"lan"},
		},
		ndp.NewMTU(uint32(s.iface.MTU)),
		&ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      s.iface.HardwareAddr,
		},
	)

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  30 * time.Minute,
		Options:         options,
	}

	mb, err := ndp.MarshalMessage(ra)
	if err != nil {
		return err
	}
	log.Printf("sending to %s", addr)
	if _, err := s.pc.WriteTo(mb, nil, addr); err != nil {
		return err
	}
	return nil
}
