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
	"cmp"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/rtr7/router7/internal/dhcp4d"
	"github.com/rtr7/router7/internal/diag"
	"github.com/rtr7/router7/internal/notify"
	"github.com/vishvananda/netlink"

	"golang.org/x/net/ipv6"
)

type Server struct {
	pc     *ipv6.PacketConn
	ifname string

	mu       sync.Mutex
	prefixes []net.IPNet
	iface    *net.Interface

	knownAddresses map[string][]dhcp4d.Lease
}

func NewServer() (*Server, error) {
	return &Server{
		knownAddresses: make(map[string][]dhcp4d.Lease),
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

func (s *Server) expireLeases() {
	now := time.Now().Round(time.Second).Add(time.Second)
	for hwAddr, leases := range s.knownAddresses {
		s.knownAddresses[hwAddr] = slices.DeleteFunc(leases, func(l dhcp4d.Lease) bool { return l.Expiry.Before(now) })
	}
}

func (s *Server) addKnownLeases(hwAddr string, lease dhcp4d.Lease) {
	leases := s.knownAddresses[hwAddr]
	leases = append(leases, lease)
	slices.SortFunc(leases, func(a, b dhcp4d.Lease) int {
		// fe80 aka link local addresses will always sort last so we reverse the condition
		// we want link local first so that ipv6 will resolve to local addresses especially
		// since gokrazy only listens on private addresses
		return cmp.Or(cmp.Compare(a.Addr.String(), b.Addr.String()), a.Expiry.Compare(b.Expiry)*-1)
	})
	s.knownAddresses[hwAddr] = slices.CompactFunc(leases, func(a, b dhcp4d.Lease) bool { return a.Addr.String() == b.Addr.String() })
}

func (s *Server) UpdateDNS(u netlink.NeighUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLeases()
	if u.State&(netlink.NUD_INCOMPLETE|netlink.NUD_PROBE|netlink.NUD_DELAY) != 0 {
		return nil
	}
	if u.State&netlink.NUD_REACHABLE == 0 {
		return fmt.Errorf("neighbor %s is not reachable (state %#x)", u.IP, u.State)
	}
	if u.IP.IsLinkLocalUnicast() || u.IP.IsMulticast() {
		return nil
	}
	hw := u.HardwareAddr
	if len(hw) == 0 {
		// Ignore updates that do not provide the MAC
		log.Printf("Ignoring neighbor update(no mac): %v", u.IP)
		return nil
	}

	leases, err := getLeases()
	if err == nil {
		for _, knownLeases := range s.knownAddresses {
			for _, lease := range knownLeases {
				if lease.Hostname != "" {
					continue
				}
				lease.Hostname = leases[lease.HardwareAddr]
			}
		}
	}
	if _, ok := leases[hw.String()]; !ok {
		log.Println("Ignoring neighbor update(no dhcp4 lease for mac):", u.IP)
		return nil
	}
	now := time.Now().Round(time.Minute)
	log.Printf("Found IPv6 address %s for MAC address %s (%s)", u.IP, hw, leases[hw.String()])
	s.addKnownLeases(hw.String(), dhcp4d.Lease{
		Addr:         u.IP,
		HardwareAddr: hw.String(),
		LastACK:      now,
		Expiry:       now.Add(30 * time.Minute), // This matches RouterLifetime below
		Hostname:     leases[hw.String()],
	})
	addresses := make([]dhcp4d.Lease, 0, len(s.knownAddresses)*2)
	for _, knownLeases := range s.knownAddresses {
		for _, lease := range knownLeases {
			addresses = append(addresses, lease)
		}
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
	if err := s.pc.SetICMPFilter(&filter); err != nil {
		return err
	}

	updates := make(chan netlink.NeighUpdate, 10)

	go func() {
		for neigh := range updates {
			if neigh.IP.To4() != nil {
				continue
			}
			err = s.UpdateDNS(neigh)
			if err != nil {
				log.Printf("Failed to update dns %v %#v", err, neigh)
			}
		}
	}()
	if err := netlink.NeighSubscribe(updates, nil); err != nil {
		log.Printf("Failed to listen for ipv6 neighbor updates %v", err)
	}

	go func() {
		for {
			for _, leases := range s.knownAddresses {
				for _, l := range leases {
					netlink.NeighSet(&netlink.Neigh{
						LinkIndex: s.iface.Index,
						Family:    syscall.AF_INET6,
						IP:        l.Addr,
						Flags:     netlink.NTF_USE,
					})
				}
			}
			time.Sleep(30 * time.Minute)
		}
	}()

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
	conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{IP: net.IPv6unspecified, Zone: ""})
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

	options = append(
		options,
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
