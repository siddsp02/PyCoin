/**
 * @file siphash.cpp
 * @author Siddharth Pai (sidd.s.pai@gmail.com, sidd.pai@ucalgary.ca)
 * @brief Siphash-2-4 implementation in C++ (WIP -- not added yet).
 * @version 0.1
 * @date 2022-04-04
 *
 * @copyright Copyright (c) 2022
 *
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <array>
#include <cassert>
#include <immintrin.h>  // Vectorization (can potentially speed up, although unlikely to be used).



