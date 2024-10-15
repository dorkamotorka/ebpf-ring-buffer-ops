# ebpf-ring-buffer-sampling

Demo Repository for eBPF Ring Buffer Rate Limiting &amp; Multithreading

- `normal`: Setup without any optimizations
- `rate-limit`: Setup with a rate-limit of 1 seconds (event is forwarded to the userspace only if 1 second has passed from the previous sent event)
- `spawned`: This has a single consumption point from the Ring Buffer, but dispatched the event to separate goroutines for further processing and allowing the program to again start consuming data from the ring buffer.
- `prespawned`: This spawns X goroutines and within each consumes from the Ring Buffer. Earlier test showed this dispatched events to threads in a ROUND ROBIN fashion.
- `rate-limit-multi`: `rate-limit` + `spawned`

## How to run

To run the program in any of the directories, follow these steps:

```
go generate
go build
sudo ./<binary-name> -i <your-net-interface> # Find network interfaces using `ip a`
```
- In another terminal run a HTTP Server:
```
python3 -m http.server 80 
```
- Make the curl request to the HTTP server and inspect the eBPF logs `sudo bpftool prog trace`
