TARGET := processor

SRC_DIR := src
INC_DIR := include

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX := g++
CXXFLAGS := -std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

SRCS :=	$(SRC_DIR)/decoder.c \
	$(SRC_DIR)/deformatter.c \
	$(SRC_DIR)/disassembler.c \
	$(SRC_DIR)/utils.c \
	$(SRC_DIR)/processor.c

OBJS := $(SRCS:.c=.o)

FIB_TEST := tests/fib
BRANCHES_TEST := tests/branches


all: $(TARGET)

debug: CXXFLAGS += -DDEBUG_BUILD
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS)

test: fib-test branches-test

fib-test:
	make -C $(FIB_TEST) test

branches-test:
	make -C $(BRANCHES_TEST) test

clean:
	rm -rf $(OBJS) $(TARGET)

dist-clean: clean
	make -C $(FIB_TEST) clean
	make -C $(BRANCHES_TEST) clean

.PHONY: all debug test fib-test branches-test clean dist-clean
