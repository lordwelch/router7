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

// Binary dhcp4 obtains a DHCPv4 lease, persists it to
// /perm/dhcp4/wire/lease.json and notifies netconfigd.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/renameio"
	"github.com/jpillora/backoff"
	"github.com/rtr7/router7/internal/dhcp4"
	"github.com/rtr7/router7/internal/netconfig"
	"github.com/rtr7/router7/internal/notify"
	"github.com/rtr7/router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var (
	netInterface = flag.String("interface", "uplink0", "network interface to operate on")
	stateDir     = flag.String("state_dir", "/perm/dhcp4", "directory in which to store lease data (wire/lease.json) and last ACK (wire/ack)")
	perm         = flag.String("perm", "/perm", "path to replace /perm")
)

func logic() error {
	leasePath := filepath.Join(*stateDir, "wire/lease.json")
	if err := os.MkdirAll(filepath.Dir(leasePath), 0755); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(*netInterface)
	if err != nil {
		return err
	}
	hwaddr := iface.HardwareAddr
	// The interface may not have been configured by netconfigd yet and might
	// still use the old hardware address. We overwrite it with the address that
	// netconfigd is going to use to fix this issue without additional
	// synchronization.
	details, err := netconfig.Interface(*perm, *netInterface)
	if err == nil {
		if spoof := details.SpoofHardwareAddr; spoof != "" {
			if addr, err := net.ParseMAC(spoof); err == nil {
				hwaddr = addr
			}
		}
	}
	ackFn := filepath.Join(*stateDir, "wire/ack")
	var ack *layers.DHCPv4
	ackB, err := ioutil.ReadFile(ackFn)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Loading previous DHCPACK packet from %s: %v", ackFn, err)
	} else {
		pkt := gopacket.NewPacket(ackB, layers.LayerTypeDHCPv4, gopacket.DecodeOptions{})
		if dhcp, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
			ack = dhcp
		}
	}
	c := dhcp4.Client{
		Interface: iface,
		HWAddr:    hwaddr,
		Ack:       ack,
	}
	usr2 := make(chan os.Signal, 1)
	signal.Notify(usr2, syscall.SIGUSR2)
	backoff := backoff.Backoff{
		Factor: 2,
		Jitter: true,
		Min:    10 * time.Second,
		Max:    1 * time.Minute,
	}
	for c.ObtainOrRenew() {
		if err := c.Err(); err != nil {
			dur := backoff.Duration()
			log.Printf("Temporary error: %v (waiting %v)", err, dur)
			time.Sleep(dur)
			continue
		}
		backoff.Reset()
		log.Printf("lease: %+v", c.Config())
		b, err := json.Marshal(c.Config())
		if err != nil {
			return err
		}
		if err := renameio.WriteFile(leasePath, b, 0644); err != nil {
			return fmt.Errorf("persisting lease to %s: %v", leasePath, err)
		}
		buf := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			},
			c.Ack,
		)
		if err := renameio.WriteFile(ackFn, buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("persisting DHCPACK to %s: %v", ackFn, err)
		}
		if err := notify.Process(path.Join(path.Dir(os.Args[0]), "/netconfigd"), syscall.SIGUSR1); err != nil {
			log.Printf("notifying netconfig: %v", err)
		}
		select {
		case <-time.After(time.Until(c.Config().RenewAfter)):
			// fallthrough and renew the DHCP lease
		case <-usr2:
			log.Printf("SIGUSR2 received, sending DHCPRELEASE")
			if err := c.Release(); err != nil {
				return err
			}
			os.Exit(125) // quit supervision by gokrazy
		}
	}
	return c.Err() // permanent error
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if *stateDir == "/perm/dhcp4" && *perm != "/perm" {
		*stateDir = strings.Replace(*stateDir, "/perm", *perm, 1)
	}
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
