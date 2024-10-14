# ebpf-ring-buffer-sampling

Demo Repository for eBPF Ring Buffer Rate Limiting &amp; Multithreading

- `normal`: Setup without any optimizations
- `rate-limit`: Setup with a rate-limit of 1 seconds (event is forwarded to the userspace only if 1 second has passed from the previous sent event)
- `spawned`: This has a single consumption point from the Ring Buffer, but dispatched the event to separate goroutines for further processing and allowing the program to again start consuming data from the ring buffer.
- `prespawned`: This spawns X goroutines and within each consumes from the Ring Buffer. Earlier test showed this dispatched events to threads in a ROUND ROBIN fashion.
- `rate-limit-multi`: `rate-limit` + `spawned`

## How to run

To run the program, follow these steps:

- First build and run the docker container with all the dependencies:
```
docker buildx create --name mybuilder --bootstrap --use
docker buildx build --push --platform linux/arm64,linux/amd64 --tag dorkamotorka/ubuntu-ebpf -f Dockerfile .
docker run --rm -it -v ./rate-limit:/rate-limit --privileged -h test --name test --env TERM=xterm-color dorkamotorka/ubuntu-ebpf
```

You can also just use `docker compose up -d` directly. Make sure to set the directory you want to mount (`volumes` configuration).

- Exec into the container:
```
docker container ls # Find the container ID
docker exec -it <container-hash> /bin/bash
cd multiratelimit
go generate
go build
sudo ./multiratelimit -i eth0
```
- Make a `curl` request to that IP:
```
curl http://172.18.0.10
```
