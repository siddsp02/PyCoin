/**
 * @file fastinv.cpp
 * @author Siddharth Pai (sidd.s.pai@gmail.com, sidd.pai@ucalgary.ca)
 * @brief Fast modular inversion (WIP -- not added).
 * @version 0.1
 * @date 2022-04-03
 *
 * @copyright Copyright (c) 2022
 *
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <iostream>
#include <tuple>

 /* The intention of all the code below was to provide a faster way
    to calculate modular inverses through a C++ Python extension.
    While calculations are roughly an order of magnitude faster for
    smaller integers (unsigned long long range in C/C++), multiprecision
    arithmetic has fairly bad performance due to reference counting
    not being completely fixed, as well multiprecision arithmetic being
    fairly slow in Python (Python only uses Karatsuba for large integer
    multiplication, as opposed to GMP's various algorithms).

    Only the plain extended euclidian algorithm is used. Some speed can
    be gained from using the prime version of modinv, although it suffers
    from memory leaks for Python long types.
 */

 /**
  * @brief Returns the bit length of an integer, which is the position of
  * the most significant bit that is set.
  *
  * @param n
  * @return int64_t
  */
int64_t bit_length(int64_t n) {
    return (n >= 2) ? bit_length(n >> 1) + 1 : 1;
}

int64_t modexp_64(int64_t g, int64_t k, int64_t p) {
    int64_t r = g;
    k %= (p - 1);
    int64_t bits = bit_length(k) - 2;
    int64_t mask = 1 << bits;
    for (int i = 0; i <= bits; ++i) {
        r = r * r % p;
        if (k & mask)
            r = r * g % p;
        mask >>= 1;
    }
    return r;
}

int64_t modinv_64(int64_t a, int64_t n) {
    int64_t t1 = 0, t2 = 1, r1 = n, r2 = a, q;
    while (r2 != 0) {
        q = r1 / r2;
        std::tie(t1, t2) = std::make_tuple(t2, t1 - q * t2);
        std::tie(r1, r2) = std::make_tuple(r2, r1 - q * r2);
    }
    if (r1 > 1)
        return 0;
    if (t1 < 0)
        t1 += n;
    return t1;
}

int64_t modinv_64_prime(int64_t a, int64_t n) {
    int64_t u = 1, w = 0, c = n, q, r, old_u;
    while (c != 0) {
        q = a / c, r = a % c;
        a = c, c = r;
        old_u = u;
        u = w;
        w = old_u - q * w;
    }
    return u;
}

static PyObject *modexp(PyObject *self, PyObject *args) {
    PyObject *g, *k, *p;
    if (PyArg_ParseTuple(args, "OOO", &g, &k, &p)) {
        if (_PyLong_NumBits(g) <= 64 && _PyLong_NumBits(k) <= 64) {
            if (_PyLong_NumBits(p) <= 64) {
                int64_t result = modexp_64(PyLong_AsLongLong(g), PyLong_AsLongLong(k), PyLong_AsLongLong(p));
                return PyLong_FromLongLong(result);
            }
        }
    }
    return NULL;
}

PyObject *_primeinv(PyObject *a, PyObject *n) {
    PyObject *u, *w, *c, *q, *r, *old_u, *d_r, *z, *o, *qw;
    u = PyLong_FromLong(1);
    w = PyLong_FromLong(0);
    Py_INCREF(a);
    Py_INCREF(n);
    z = Py_NewRef(w);
    o = Py_NewRef(u);
    c = Py_NewRef(n);
    while (PyObject_RichCompareBool(c, z, Py_NE)) {
        d_r = PyNumber_Divmod(a, c);
        q = PyTuple_GetItem(d_r, 0);
        r = PyTuple_GetItem(d_r, 1);
        Py_DECREF(a);
        a = c, c = r;  // Avoid increasing reference count (adds overhead).
        old_u = u;
        u = w;
        qw = PyNumber_Multiply(q, u);
        w = PyNumber_Subtract(old_u, qw);
        Py_DECREF(qw);
        Py_DECREF(old_u);
        /* This is where the memory leak is. Decrementing the
           reference count results in the function not returning
           properly, so this has to be fixed. */

           /* Py_DECREF(d_r); */
    }
    Py_DECREF(w);
    Py_DECREF(z);
    Py_DECREF(o);
    Py_DECREF(c);
    return u;
}

PyObject *primeinv(PyObject *self, PyObject *args) {
    PyObject *a, *n;
    if (!PyArg_ParseTuple(args, "OO", &a, &n))
        return NULL;
    if (PyLong_CheckExact(a) && PyLong_CheckExact(n)) {
        if (_PyLong_NumBits(a) <= 64 && _PyLong_NumBits(n) <= 64) {
            int64_t result = modinv_64_prime(PyLong_AsLongLong(a), PyLong_AsLongLong(n));
            return PyLong_FromLongLong(result);
        }
        return _primeinv(a, n);
    }
    return NULL;
}

/*
    Regular extended euclidean algorithm for modular inverse.
    This can also be viewed in the test framework for the Bitcoin Core repository.

    Python equivalent:

    def modinv(a: int, n: int) -> int:
        t1, t2, r1, r2 = 0, 1, n, a
        while r2 != 0:
            q = r1 // r2
            t1, t2 = t2, t1 - q*t2
            r1, r2 = r2, r1 - q*r2
        if r1 > 1:
            return 0
        if t1 < 0:
            t1 += n
        return t1

*/

static PyObject *modinv(PyObject *self, PyObject *args) {
    PyObject *ar, *nr;
    if (PyArg_ParseTuple(args, "OO", &ar, &nr)) {
        if (PyLong_CheckExact(ar) && PyLong_CheckExact(nr)) {
            if (_PyLong_NumBits(ar) <= 64 && _PyLong_NumBits(nr) <= 64) {
                int64_t result = modinv_64(PyLong_AsLongLong(ar), PyLong_AsLongLong(nr));
                return PyLong_FromLongLong(result);
            }
            PyObject *r1, *old_r1, *r2, *old_r2, *t1, *old_t1, *t2, *old_t2, *z, *q, *o;
            o = PyLong_FromLong(1);
            z = PyLong_FromLong(0);
            t1 = Py_NewRef(z);
            t2 = Py_NewRef(o);
            r1 = Py_NewRef(nr);
            r2 = Py_NewRef(ar);
            while (PyObject_RichCompareBool(r2, z, Py_NE)) {
                q = PyNumber_FloorDivide(r1, r2);
                old_t1 = t1;
                t1 = t2;
                t2 = PyNumber_Multiply(q, t1);
                old_t2 = t2;
                t2 = PyNumber_Subtract(old_t1, t2);
                Py_DECREF(old_t1);
                Py_DECREF(old_t2);
                old_r1 = r1;
                r1 = r2;
                r2 = PyNumber_Multiply(q, r1);
                old_r2 = r2;
                Py_DECREF(q);
                r2 = PyNumber_Subtract(old_r1, r2);
                Py_DECREF(old_r1);
                Py_DECREF(old_r2);
            }
            Py_DECREF(t2);
            Py_DECREF(r2);
            if (PyObject_RichCompareBool(r1, o, Py_GT)) {
                Py_DECREF(t1);
                Py_DECREF(r1);
                Py_DECREF(o);
                Py_DECREF(z);
                return Py_None;
            }
            if (PyObject_RichCompareBool(t1, z, Py_LT)) {
                old_t1 = t1;
                t1 = PyNumber_Add(t1, nr);
                Py_DECREF(old_t1);
            }
            Py_DECREF(r1);
            Py_DECREF(o);
            Py_DECREF(z);
            return t1;
        } else {
            return NULL;
        }
    }
    return NULL;
};

static PyMethodDef FastInvMethods[] = {
    {"modinv", modinv, METH_VARARGS, "Find the modular inverse of a mod n."},
    {"modexp", modexp, METH_VARARGS, "Find the modular exponentiation of g**k mod p."},
    {"primeinv", primeinv, METH_VARARGS, "Find the modular inverse of a mod n, given that n is prime."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef fastinv = {
    PyModuleDef_HEAD_INIT,
    "fastinv",
    NULL,
    -1,
    FastInvMethods
};

PyMODINIT_FUNC PyInit_fastinv(void) {
    return PyModule_Create(&fastinv);
}
