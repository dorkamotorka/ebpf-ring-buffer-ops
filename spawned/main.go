package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go spawned spawned.c

import (
    "log"
    "net"
    "flag"
    "sync"
    "time"

    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

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

    rd, err := ringbuf.NewReader(objs.RingbufMap)
    if err != nil {
	panic(err)
    }
    defer rd.Close()

    // Create a wait group to synchronize goroutines
    var wg sync.WaitGroup

    count := 0
    maxCount := 1000
    var startTime time.Time
    for {
	if count >= maxCount {
	    break
        }
	_, err := rd.Read()
	if err != nil {
	    if err == ringbuf.ErrClosed {
		return
	    }
	    log.Printf("reading from ringbuf: %v", err)
	    continue
	}

	if count == 0 {
            startTime = time.Now()
        }

	wg.Add(1)
	go func() {
	    defer wg.Done()
    	    time.Sleep(200 * time.Millisecond)
	    log.Printf("Received bpf event into userspace...\n")
	}()
	count++
    }

    // Wait for goroutines to finish
    wg.Wait()

    // Record the end time
    endTime := time.Now()

    // Calculate the elapsed time
    elapsedTime := endTime.Sub(startTime)

    log.Printf("Total time taken for 999 iterations (after the first): %s\n", elapsedTime)
}
