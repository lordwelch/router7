package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"path"

	"github.com/gokrazy/gokrazy"
)

// buildTimestamp can be overridden by specifying e.g.
// -ldflags "-X main.buildTimestamp=foo" when building.
var (
	buildTimestamp = "2020-06-08T19:45:52-07:00"

	domain     string
	cmdRoot    string
	perm       string
	noFirewall bool
)

func main() {
	flag.StringVar(&cmdRoot, "cmdroot", "/usr/bin", "path to rtr7 binaries")
	flag.StringVar(&domain, "domain", "lan", "domain name for your network")
	flag.StringVar(&perm, "perm", "/var/lib/rtr7/", "path to replace /perm")
	flag.BoolVar(&noFirewall, "nofirewall", false, "disable the rtr7 firewall")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Printf("gokrazy build timestamp %s\n", buildTimestamp)

	cmds := []*exec.Cmd{
		// exec.Command(path.Join(cmdRoot, "/ntp")),
		exec.Command(path.Join(cmdRoot, "backupd"), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "captured"), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "dhcp4"), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "dhcp4d"), fmt.Sprintf("-domain=%s", domain), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "dhcp6"), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "diagd"), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "dnsd"), fmt.Sprintf("-domain=%s", domain), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "dyndns"), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "netconfigd"), fmt.Sprintf("-nofirewall=%t", noFirewall), "-perm="+perm),
		exec.Command(path.Join(cmdRoot, "radvd"), "-perm="+perm),
	}
	if err := gokrazy.Supervise(cmds); err != nil {
		log.Fatal(err)
	}
	select {}
}
