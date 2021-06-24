INC_DIR := ../../include

LIBCSDEC := ../../libcsdec.a

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX := g++
CXXFLAGS := -Wall
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

OBJS := test_lib.o
PROGRAM := test_lib


test: $(PROGRAM)
	./test.sh
	./test_lib

$(PROGRAM): $(OBJS)
	$(CXX) -o $@ $^ $(LIBCSDEC) $(CXXFLAGS)

clean:
	rm -f trace*_edge_coverage.out trace*_bitmap.out
	rm -f test_lib.o test_lib

.PHONY: test clean
