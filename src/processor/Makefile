TARGET = main

all: $(TARGET)
.PHONY: all

$(TARGET): $(TARGET).o config.o
	g++ -Wall -o $(TARGET) $(TARGET).o ../common/config.o

$(TARGET).o: $(TARGET).cxx
	g++ -Wall -o $(TARGET).o -c $(TARGET).cxx

config.o: ../common/config.c
	g++ -Wall -o ../common/config.o -c ../common/config.c

clean:
	- rm $(TARGET).o
	- rm ../common/config.o
	- rm $(TARGET)
