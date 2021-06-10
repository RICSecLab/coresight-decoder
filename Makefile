TARGET := processor

CXX := g++
CXXFLAGS :=-std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG

# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME := capstone

SRCS := decoder.c deformatter.c disassembler.c utils.c processor.c
OBJS := $(SRCS:.c=.o)

FIB_TEST := tests/fib

all: $(TARGET)

debug: CXXFLAGS += -DDEBUG_BUILD
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -l$(LIBNAME) -o $@

test: fib-test

fib-test:
	make -C $(FIB_TEST) test

clean:
	rm -rf *.o $(TARGET)

dist-clean: clean
	make -C $(FIB_TEST) clean

.PHONY: all debug test fib-test clean dist-clean
