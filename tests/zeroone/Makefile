TARGET := test

LIBBOOST := boost_unit_test_framework

CXX := g++
CXXFLAGS := -std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG
CXXFLAGS += -l$(LIBBOOST)

SRCS :=	test.cpp
OBJS := $(SRCS:.c=.o)

PROC_TRACE_DIR?=


all: run test

run:
	rm -rf trace && mkdir trace
	./run.sh $(realpath $(PROC_TRACE_DIR))

build: $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS)

test: build
	./test

clean:
	rm -rf $(OBJS) $(TARGET) trace

.PHONY: all build run test clean
