#pragma once
#include <cstdint>

// Raw views of memory, for the fields and frames that named logging misses.
// Lifted unchanged in behaviour from Flight Freedom's conditions.cpp, which is
// where they were written and where the reasoning behind them is recorded: when
// a value is not where it was expected, the log should already contain the
// place it actually is, rather than needing another build and another launch.
namespace bp::dump
{
    // Qwords of an object, with a class name wherever RTTI resolves one. The
    // non-pointer values matter as much as the pointers: a row key or a type
    // enum lives among them.
    void Object(const char* what, uintptr_t obj, unsigned bytes);

    // Every image address on 4 KB of the calling thread's stack, marked as a
    // return address where the bytes before it decode as a call. The unwinder
    // in sites.cpp stops at the first frame it cannot describe; this does not.
    void Stack(const char* why);
}
