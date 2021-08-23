INC_DIR := ../../include

LIBCSDEC := ../../libcsdec.a

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX := g++
CXXFLAGS := -Wall -O3 -std=c++17 -g
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

EDGE_COV_MODE := 1
PATH_COV_MODE := 0

ifeq ($(EDGE_COV_MODE), 1)
	CXXFLAGS += -DEDGE_COV
endif

ifeq ($(PATH_COV_MODE), 1)
	CXXFLAGS += -DPATH_COV
endif

OBJS := test.o
PROGRAM := test


$(PROGRAM): $(OBJS) $(LIBCSDEC)
	$(CXX) -o $@ $^ $(LIBCSDEC) $(CXXFLAGS)

clean:
	rm -f test.o test

.PHONY: clean
