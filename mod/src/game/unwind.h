#pragma once

// A real unwind of the calling thread, frame by frame through the unwind
// tables, as opposed to dump::Stack's raw scan for anything that looks like
// a return address. The scan finds stale frames from earlier calls on the
// same stack and prints them in with the live ones; session seven's refusal
// stack had a scope-attacher helper in it that was never on the path. This
// walks RtlVirtualUnwind from the current context and stops at the first
// frame without an unwind entry, so what it prints is the call chain.
namespace bp::unwind
{
    void Here(const char* why, int maxFrames);
}
