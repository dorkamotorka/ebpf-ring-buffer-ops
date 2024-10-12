# ebpf-ring-buffer-sampling

Demo Repository for eBPF Ring Buffer Rate Limiting &amp; Multithreading

## Multithreaded Ring Buffer Consumer

**NOTE**: This is experimental and a work in progress.

This project provides an implementation of a ring buffer (circular buffer) with multithreaded consumer capabilities. It is designed to efficiently handle concurrent data consumption using multiple threads.

### Two Multithreaded Concepts

There are two concepts, you will find in this repository. Namely:

- **spawn**: This has a single consumption point from the Ring Buffer, but dispatched the event to separate threads for further processing and allowing the program to again start consuming data from the ring buffer.
- **prespawn**: This spawns X threads and within each threads consumes from the Ring Buffer. Earlier test showed this dispatched events to threads in a ROUND ROBIN fashion.
