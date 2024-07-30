nic := lo
CFLAGS :=

vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

prism.o: prism.bpf.c vmlinux.h
	clang ${CFLAGS} -target bpf -g -O2 -c -o prism.o prism.bpf.c

load: prism.o
	sudo xdp-loader load -m skb -s xdp.prism ${nic} prism.o

unload:
	sudo xdp-loader unload -a ${nic}

clean:
	rm prism.o
