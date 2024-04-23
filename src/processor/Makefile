TARGET = main

all: $(TARGET)
.PHONY: all

$(TARGET): $(TARGET).o config.o processor.o mmf.o
	g++ -Wall -o $(TARGET) $(TARGET).o config.o processor.o mmf.o -lmagic

$(TARGET).o: $(TARGET).cxx
	g++ -Wall -o $(TARGET).o -c $(TARGET).cxx

config.o: ../common/config.cxx
	g++ -Wall -o config.o -c ../common/config.cxx

processor.o: processor.cxx
	g++ -Wall -o processor.o -c processor.cxx

mmf.o: ../common/mmf.c
	g++ -Wall -o mmf.o -c ../common/mmf.c

clean:
	- rm $(TARGET).o
	- rm config.o mmf.o processor.o
	- rm $(TARGET)
