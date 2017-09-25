CXXFILES := $(wildcard *.cxx)
OBJS     := $(patsubst %.cxx, %.o, $(CXXFILES))

CXX      := clang++
CXXFLAGS := -m32 -Wall -Wno-c++11-extensions -g
LDFLAGS  := -arch i386
LDLIBS   := 

.PHONY: all clean examples

all: winoux examples

winoux: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(MAKE) --directory=examples clean
	rm -f *.o winoux

examples:
	$(MAKE) --directory=$@

%.o: %.cxx
	$(CXX) $(CXXFLAGS) -c $< -o $@
