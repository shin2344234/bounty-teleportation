#pragma once

#include <Windows.h>

namespace bp::Mod
{
    void Initialize(HMODULE module);
    void Shutdown(bool processExiting);
}
