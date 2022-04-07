/**
 * @file miner.cpp
 * @author Siddharth Pai (sidd.s.pai@gmail.com, sidd.pai@ucalgary.ca)
 * @brief C++ Python Extension for Bitcoin mining (WIP -- not added yet).
 * @version 0.1
 * @date 2022-04-01
 *
 * @copyright Copyright (c) 2022
 *
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

bool verify_header(PyObject *header) {
    return;
}

inline uint32_t check_nonce(PyObject *header, uint32_t nonce) {
    return;
}

bool check_nonce_range(PyObject *header, uint32_t start, uint32_t end) {
    return false;
}

PyObject *mine(PyObject *self, PyObject *args) {
    PyObject *header;
    if (!PyArg_ParseTuple(args, "O", &header)) {
        return NULL;
    }
    for (uint32_t i = 0; i < UINT32_MAX; ++i) {
        ;
    }
    return;
}

static PyMethodDef MinerMethods[] = {
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef miner = {
    PyModuleDef_HEAD_INIT,
    "miner",
    NULL,
    -1,
    MinerMethods
};

PyMODINIT_FUNC PyInit_fastinv(void) {
    return PyModule_Create(&miner);
}
