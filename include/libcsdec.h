/** @file
    libcsdec C wrapper library header.
**/
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <limits.h>

/**
    Represents the libcsdec decoder context.
**/
typedef void* libcsdec_t;

/**
    Represents an executable memory image.
**/
struct libcsdec_memory_image {
    void* data;     /**< Binary data of the memory image. */
    size_t size;    /**< Size of the memory image. */
};

/**
    Represents an executable memory mapped region.
**/
struct libcsdec_memory_map {
    unsigned long start;    /**< Start address of the memory map. */
    unsigned long end;      /**< End address of the memory map. */
    char path[PATH_MAX];    /**< Path to the executable. */
};

/**
    Defines libcsdec specific return code.
**/
typedef enum libcsdec_result {
    LIBCSDEC_SUCCESS,                       /**< Suceeded. */
    LIBCSDEC_ERROR,                         /**< Failed. */
    LIBCSDEC_ERROR_OVERFLOW_PACKET,         /**< Failed due to the overflow packet exists. */
    LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE,   /**< Failed due to the trace data is incomplete. */
    LIBCSDEC_ERROR_PAGE_FAULT               /**< Failed due to the invalid address. */
} libcsdec_result_t;

libcsdec_t libcsdec_init_edge(
    void *bitmap_addr, int bitmap_size,
    int memory_image_num,
    const struct libcsdec_memory_image libcsdec_memory_image[]);

libcsdec_result_t libcsdec_reset_edge(
    const libcsdec_t libcsdec,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);

libcsdec_result_t libcsdec_run_edge(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size);

libcsdec_result_t libcsdec_finish_edge(const libcsdec_t libcsdec);


libcsdec_t libcsdec_init_path(
    void *bitmap_addr, int bitmap_size,
    int memory_image_num,
    const struct libcsdec_memory_image libcsdec_memory_image[]);

libcsdec_result_t libcsdec_reset_path(
    const libcsdec_t libcsdec,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);

libcsdec_result_t libcsdec_run_path(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size);

libcsdec_result_t libcsdec_finish_path(const libcsdec_t libcsdec);

#ifdef __cplusplus
} // extern "C"
#endif
