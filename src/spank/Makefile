
USER_C = ../ebpf/opentracer.c \
		 ../common/config.c \
		 ../common/mmf.c \
		 ../storage/simple_storage.cxx \
		 ../storage/database.cxx \
		 spank_plugin.c \
		 ../processor/processor.cxx
COMMON_H = ../ebpf/opentracer.h
LIBS = -lbpf -lelf -lz -pthread -lmagic -lsqlite3

all: ebpf libopentracer.so

ebpf:
	make -C ../ebpf
	cp ../ebpf/opentracer.bpf.o .

libopentracer.so: $(USER_C) $(USER_SKEL) $(COMMON_H)
	g++ -DOPENTRACER_USERSPACE=1 -shared -fPIC -o libopentracer.so $(USER_C) -ldl $(LIBS) -Wall

local:
	g++ -o local_test $(USER_C) $(LIBS) -Wall

clean:
	- rm libopentracer.so
	- rm opentracer.bpf.o
	- make -C ../ebpf clean
	- rm local_test