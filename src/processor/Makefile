TARGET = main

all: $(TARGET)
.PHONY: all

$(TARGET): $(TARGET).o
	g++ -Wall -o $(TARGET) $(TARGET).o

$(TARGET).o: $(TARGET).cxx
	g++ -Wall -o $(TARGET).o -c $(TARGET).cxx

clean:
	- rm $(TARGET).o
	- rm $(TARGET)
