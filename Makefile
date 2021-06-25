TARGET := processor
LIBTARGET := libcsdec.a

SRC_DIR := src
INC_DIR := include

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX := g++
CXXFLAGS := -std=c++14 -Wall
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

SRCS :=	$(SRC_DIR)/decoder.c \
	$(SRC_DIR)/deformatter.c \
	$(SRC_DIR)/disassembler.c \
	$(SRC_DIR)/utils.c \
	$(SRC_DIR)/bitmap.c \
	$(SRC_DIR)/common.c \
	$(SRC_DIR)/cache.c \
	$(SRC_DIR)/trace.c \
	$(SRC_DIR)/process.c \
	$(SRC_DIR)/libcsdec.c \
	$(SRC_DIR)/processor.c

OBJS := $(SRCS:.c=.o)

FIB_TEST := tests/fib
BRANCHES_TEST := tests/branches


all: $(TARGET) $(LIBTARGET)

# FIXME: Enabling UBSAN and GLIBCXX_DEBUG is not compatible with proc-trace
debug: CXXFLAGS += -DDEBUG_BUILD
debug: CXXFLAGS += -g -fsanitize=undefined -D_GLIBCXX_DEBUG
debug: $(TARGET) $(LIBTARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS)

$(LIBTARGET): $(subst src/processor.o,,$(OBJS))
	$(AR) -rc $@ $^

test: fib-test branches-test

fib-test:
	make -C $(FIB_TEST) test

branches-test:
	make -C $(BRANCHES_TEST) test

clean:
	rm -rf $(OBJS) $(TARGET) $(LIBTARGET)

dist-clean: clean
	make -C $(FIB_TEST) clean
	make -C $(BRANCHES_TEST) clean

.PHONY: all debug test fib-test branches-test clean dist-clean
