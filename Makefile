SUDO=GOPATH=$(shell go env GOPATH) sudo --preserve-env=GOPATH

PKGS := github.com/rtr7/router7/cmd/... \
	github.com/gokrazy/breakglass \
	github.com/gokrazy/timestamps \
	github.com/stapelberg/zkj-nas-tools/wolgw \
	github.com/gokrazy/gdns

build:
	mkdir -p result
	GOOS=linux go build -o ./result github.com/rtr7/router7/cmd/...
	GOOS=linux go build -o ./result/rtr7-init -ldflags "-X main.buildTimestamp=$(shell date '+%Y-%m-%dT%H:%M:%S%z') -X github.com/gokrazy/gokrazy.httpPassword=temp" init/init.go

clean:
	rm -rf result
	go clean -cache

image:
ifndef DIR
	@echo variable DIR unset
	false
endif
	go install github.com/gokrazy/tools/cmd/gokr-packer
	GOARCH=amd64 gokr-packer \
		-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp,github.com/gokrazy/gokrazy/cmd/randomd \
		-kernel_package=github.com/rtr7/kernel \
		-firmware_package=github.com/rtr7/kernel \
		-eeprom_package= \
		-overwrite_boot=${DIR}/boot.img \
		-overwrite_root=${DIR}/root.img \
		-overwrite_mbr=${DIR}/mbr.img \
		-serial_console=ttyS0,115200n8 \
		-hostname=router7 \
		${PKGS}

recover: #test
	go install \
		github.com/gokrazy/tools/cmd/gokr-packer \
		github.com/rtr7/tools/cmd/rtr7-recover
	GOARCH=amd64 gokr-packer \
		-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp,github.com/gokrazy/gokrazy/cmd/randomd \
		-kernel_package=github.com/rtr7/kernel \
		-firmware_package=github.com/rtr7/kernel \
		-eeprom_package= \
		-overwrite_boot=/tmp/recovery/boot.img \
		-overwrite_root=/tmp/recovery/root.img \
		-serial_console=ttyS0,115200n8 \
		-hostname=router7 \
		${PKGS}
	${SUDO} /home/michael/go/bin/rtr7-recover \
		-boot=/tmp/recovery/boot.img \
		-root=/tmp/recovery/root.img

test:
	# simulate recover (quick, for early for feedback)
	go build ${PKGS} github.com/rtr7/tools/cmd/...
	go test -count=1 -v -race github.com/rtr7/router7/internal/...
	# integration tests
	${SUDO} $(shell go env GOROOT)/bin/go test -count=1 -v -race github.com/rtr7/router7/...

testdhcp:
	go test -v -coverprofile=/tmp/cov github.com/rtr7/router7/internal/dhcp4d
#&& go tool cover -html=/tmp/cov

strace:
	# simulate recover (quick, for early for feedback)
	go build ${PKGS} github.com/rtr7/tools/cmd/...
	go test -v -race github.com/rtr7/router7/internal/...
	# integration tests
	(cd /tmp && go test -c router7) && ${SUDO} strace -f -o /tmp/st -s 2048 /tmp/router7.test -test.v #-test.race

update:
	rtr7-safe-update -build_command='make -C ~/router7 image DIR=$GOKR_DIR'

# sudo ip link add link enp0s31f6 name macvtap0 type macvtap
# sudo ip link set macvtap0 address 52:55:00:d1:55:03 up
#
# TODO: use veth pairs for router7’s lan0?
# e.g. get a network namespace to talk through router7
# ip link add dev veth1 type veth peer name veth2
qemu:
	GOARCH=amd64 gokr-packer \
		-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp,github.com/gokrazy/gokrazy/cmd/randomd \
		-hostname=qemu-router7 \
		-kernel_package=github.com/rtr7/kernel \
		-firmware_package=github.com/rtr7/kernel \
		-eeprom_package= \
		-overwrite=/tmp/router7-qemu/disk.img \
		-target_storage_bytes=$$((2*1024*1024*1024)) \
		-serial_console=ttyS0,115200 \
		${PKGS}
	./travis/loopmkfs.sh
	# TODO: without -smp, nothing works! is that GOMAXPROCS defaulting to 1 or something?
	qemu-system-x86_64 \
		-boot order=d \
		-drive file=/tmp/router7-qemu/disk.img,format=raw \
		-netdev tap,id=uplink,fd=3 3<>/dev/tap184 \
		-device virtio-net-pci,netdev=uplink,mac=52:55:00:d1:55:03 \
		-device virtio-net-pci,id=lan,mac=52:55:00:d1:55:04 \
		-device i6300esb,id=watchdog0 -watchdog-action reset \
		-smp 8 \
		-machine accel=kvm \
		-m 4096 \
		-nographic
