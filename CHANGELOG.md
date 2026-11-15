# Release v0.24.1

## What's Changed

- Fix: in debug builds, a run on localhost overflowed the stack of a tokio worker
  thread (2 MiB; 0.24.0 needed about 2.1 MiB, 0.23.1 about 0.3 MiB). The read
  buffers of a command's output were part of its future, which debug builds copy
  along each `.await`; they are now on the heap. Release builds were not affected.
- New test: a run (live view on) fits in a 1 MiB thread stack.
