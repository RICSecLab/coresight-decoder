TARGET := processor

CXX := g++
CXXFLAGS :=-std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG

# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME := capstone

SRCS := decoder.c deformatter.c disassembler.c utils.c processor.c
OBJS := $(SRCS:.c=.o)


all: $(TARGET)

debug: CXXFLAGS += -DDEBUG_BUILD
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -l$(LIBNAME) -o $@

clean:
	rm -rf *.o $(TARGET)

.PHONY: all debug clean
