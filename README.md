# ebpf-ring-buffer-sampling

Demo Repository for eBPF Ring Buffer Rate Limiting &amp; Multithreading

## How to run

To run the program, follow these steps:

- First build and run the docker container with all the dependencies:
```
docker buildx create --name mybuilder --bootstrap --use
docker buildx build --push --platform linux/arm64,linux/amd64 --tag dorkamotorka/ubuntu-ebpf -f Dockerfile .
docker run --rm -it -v ./rate-limit:/rate-limit --privileged -h test --name test --env TERM=xterm-color dorkamotorka/ubuntu-ebpf
```

You can also just use `docker compose up -d` directly. 

- Exec into the container:
```
cd rate-limit
go generate
go build
sudo ./ratelimit -i eth0
```
- Make a `curl` request to that IP:
```
curl http://172.18.0.10
```

## Multithreaded Ring Buffer Consumer

**NOTE**: This is experimental and a work in progress.

This project provides an implementation of a ring buffer (circular buffer) with multithreaded consumer capabilities. It is designed to efficiently handle concurrent data consumption using multiple threads.

### Two Multithreaded Concepts

There are two concepts, you will find in this repository. Namely:

- **spawn**: This has a single consumption point from the Ring Buffer, but dispatched the event to separate threads for further processing and allowing the program to again start consuming data from the ring buffer.
- **prespawn**: This spawns X threads and within each threads consumes from the Ring Buffer. Earlier test showed this dispatched events to threads in a ROUND ROBIN fashion.
