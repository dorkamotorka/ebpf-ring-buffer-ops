package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go spawned spawned.c

import (
    "log"
    "net"
    "flag"
    "time"
    "sync"

    "golang.org/x/sys/unix"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func getTimeFromBootNs() uint64 {
    var ts unix.Timespec
    err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
    if err != nil {
	panic(err)
    }
    return uint64(ts.Sec)*uint64(time.Second.Nanoseconds()) + uint64(ts.Nsec)
}

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil {
	log.Fatal("Removing memlock:", err)
    }

    var ifname string
    flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF program will be attached")
    flag.Parse()

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs spawnedObjects
    if err := loadSpawnedObjects(&objs, nil); err != nil {
	log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()

    iface, err := net.InterfaceByName(ifname)
    if err != nil {
	log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach XDP program to the network interface.
    xdplink, err := link.AttachXDP(link.XDPOptions{
	Program:   objs.XdpTcpCapture,
	Interface: iface.Index,
    })
    if err != nil {
	log.Fatal("Attaching XDP:", err)
    }
    defer xdplink.Close()

    var key uint32 = 0
    currentTimeInNs := getTimeFromBootNs() 
    err = objs.spawnedMaps.RatelimitMap.Update(&key, &currentTimeInNs, ebpf.UpdateAny)
    if err != nil {
	    log.Fatalf("Failed to update the map: %v", err)
    }

    rd, err := ringbuf.NewReader(objs.RingbufMap)
    if err != nil {
	panic(err)
    }
    defer rd.Close()

    // Create a wait group to synchronize goroutines
    var wg sync.WaitGroup

    for {
	_, err := rd.Read()
	if err != nil {
	    if err == ringbuf.ErrClosed {
		return
	    }
	    log.Printf("reading from ringbuf: %v", err)
	    continue
	}

	wg.Add(1)
	go func() {
	    defer wg.Done()
    	    log.Printf("Received bpf event into userspace...\n")
	}()

    }

    // Wait for goroutines to finish
    wg.Wait()
}
