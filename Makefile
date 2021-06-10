TARGET := processor

CXX := g++
CXXFLAGS :=-std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG

# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME := capstone

SRCS := decoder.c deformatter.c disassembler.c utils.c processor.c
OBJS := $(SRCS:.c=.o)

FIB_TEST := tests/fib
BRANCHES_TEST := tests/branches

all: $(TARGET)

debug: CXXFLAGS += -DDEBUG_BUILD
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -l$(LIBNAME) -o $@

test: fib-test branches-test

fib-test:
	make -C $(FIB_TEST) test

branches-test:
	make -C $(BRANCHES_TEST) test

clean:
	rm -rf *.o $(TARGET)

dist-clean: clean
	make -C $(FIB_TEST) clean
	make -C $(BRANCHES_TEST) clean

.PHONY: all debug test fib-test branches-test clean dist-clean
