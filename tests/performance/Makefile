INC_DIR := ../../include

LIBCSDEC := ../../libcsdec.a

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX := g++
CXXFLAGS := -Wall -O3 -std=c++17
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

OBJS := test.o
PROGRAM := test


$(PROGRAM): $(OBJS)
	$(CXX) -o $@ $^ $(LIBCSDEC) $(CXXFLAGS)

clean:
	rm -f test.o test

.PHONY: clean
