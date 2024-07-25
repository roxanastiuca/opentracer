TARGET = opentracer

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}
USER_SKEL = ${TARGET:=.skel.h}

all: $(BPF_OBJ) $(USER_SKEL)

$(BPF_OBJ): %.o: $(BPF_C) vmlinux.h  $(COMMON_H)
	clang \
	    -target bpf \
		-D__TARGET_ARCH_x86 \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
