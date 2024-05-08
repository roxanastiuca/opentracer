
USER_C = ../ebpf/opentracer.c ../common/config.c ../common/mmf.c spank_plugin.c
COMMON_H = ../ebpf/opentracer.h
LIBS = -lbpf -lelf -lz

all: ebpf libopentracer.so

ebpf:
	make -C ../ebpf
	cp ../ebpf/opentracer.bpf.o .

libopentracer.so: $(USER_C) $(USER_SKEL) $(COMMON_H)
	gcc -shared -fPIC -o libopentracer.so $(USER_C) -ldl $(LIBS) -Wall

local:
	gcc -o local_test $(USER_C) $(LIBS) -Wall

clean:
	- rm libopentracer.so
	- rm opentracer.bpf.o
	- make -C ../ebpf clean
	- rm local_test