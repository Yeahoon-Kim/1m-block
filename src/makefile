CXX = g++
CXXFLAGS = -W -Wall -O2
DEBUGFLAGS = -W -Wall -g -O0
OBJECTS = ./main.o ./1m-block.o ./ipv4hdr.o ./tcphdr.o ./ip.o
DOBJECTS = ./main-test.o ./1m-block-test.o ./ipv4hdr-test.o ./tcphdr-test.o ./ip-test.o
TARGET = ../bin/1m-block
DTARGET = ../bin/1m-block-test
LIBS = -lnetfilter_queue

all: $(TARGET)
debug: $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

$(DTARGET): $(DOBJECTS)
	$(CXX) $(DEBUGFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
1m-block.o: ./1m-block.o
ipv4hdr.o: ipv4hdr.cpp
tcphdr.o: tcphdr.cpp
ip.o: ip.cpp

main-test.o: main.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
1m-block-test.o: 1m-block.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ipv4hdr-test.o: ipv4hdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
tcphdr-test.o: tcphdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ip-test.o: ip.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)

clean: 
	rm -f $(TARGET)
	rm -f $(DTARGET)
	rm -f *.o

.PHONY: all clean
