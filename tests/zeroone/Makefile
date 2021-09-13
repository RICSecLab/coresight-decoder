# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

TARGET := test

LIBBOOST := boost_unit_test_framework

CXX := g++
CXXFLAGS := -std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG
CXXFLAGS += -l$(LIBBOOST)

SRCS := test.cpp

PROC_TRACE_DIR?=


all: run-tracer run-test

run-tracer:
	rm -rf trace && mkdir trace
	./run.sh $(realpath $(PROC_TRACE_DIR))

$(TARGET): $(SRCS)
	$(CXX) -o $@ $^ $(CXXFLAGS)

run-test: $(TARGET)
	./test

clean:
	rm -rf $(TARGET) trace

.PHONY: all run-tracer run-test clean
