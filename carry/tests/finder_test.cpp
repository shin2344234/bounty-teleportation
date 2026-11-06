// Runs the finder over every game exe under a patch-baseline folder as if
// none of them were in kBuilds, and checks that what it finds is that
// build's row, field by field. Each exe is laid out by RVA the way the
// loader would, without relocations, so a pointer in the data reads as
// ImageBase plus its RVA.
//
//   FinderTest.exe <patch-baseline folder>
//
// Exits 0 when every build found matches its row, 1 otherwise.
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "builds.h"
#include "finder.h"

namespace
{
    int g_fails = 0;

    bool Load(const std::wstring& path, std::vector<uint8_t>* img, uint64_t* imageBase)
    {
        FILE* f = _wfopen(path.c_str(), L"rb");
        if (!f) return false;
        std::vector<uint8_t> file;
        _fseeki64(f, 0, SEEK_END);
        file.resize(static_cast<size_t>(_ftelli64(f)));
        _fseeki64(f, 0, SEEK_SET);
        const size_t got = fread(file.data(), 1, file.size(), f);
        fclose(f);
        if (got != file.size() || file.size() < 0x1000) return false;

        uint32_t pe;
        memcpy(&pe, file.data() + 0x3C, 4);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + pe);
        *imageBase = nt->OptionalHeader.ImageBase;
        img->assign(nt->OptionalHeader.SizeOfImage, 0);
        memcpy(img->data(), file.data(), nt->OptionalHeader.SizeOfHeaders);
        const auto* sh = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            const size_t va = sh[i].VirtualAddress, raw = sh[i].PointerToRawData;
            size_t n = sh[i].SizeOfRawData;
            if (raw >= file.size() || va >= img->size()) continue;
            if (raw + n > file.size()) n = file.size() - raw;
            if (va + n > img->size()) n = img->size() - va;
            memcpy(img->data() + va, file.data() + raw, n);
        }
        return true;
    }

    void Diff(const char* build, const char* field, unsigned long long want, unsigned long long got)
    {
        if (want == got) return;
        printf("  %s: %s is 0x%llX in the table and the finder found 0x%llX\n", build, field, want, got);
        ++g_fails;
    }

    void DiffStr(const char* build, const char* field, const char* want, const char* got)
    {
        if (!want) want = "";
        if (!got) got = "";
        if (strcmp(want, got) == 0) return;
        printf("  %s: %s is \"%s\" in the table and the finder found \"%s\"\n", build, field, want, got);
        ++g_fails;
    }

    void Compare(const bt::Build& t, const bt::Build& f)
    {
        const char* n = t.name;
        Diff(n, "catchUpdate", t.catchUpdate, f.catchUpdate);
        for (int i = 0; i < bt::kReleaseCount; ++i)
        {
            const bt::Release& a = t.releases[i];
            const bt::Release& b = f.releases[i];
            char what[64];
            DiffStr(n, "release label", a.label, b.label);
#define FIELD(x)                                                     \
    snprintf(what, sizeof what, "%s." #x, a.label);                  \
    Diff(n, what, static_cast<unsigned long long>(a.x), static_cast<unsigned long long>(b.x))
            FIELD(at);
            FIELD(orig[0]);
            FIELD(orig[1]);
            FIELD(repl[0]);
            FIELD(repl[1]);
            FIELD(call);
            FIELD(guard);
            FIELD(shapeLen);
            FIELD(vtable);
            FIELD(slotTarget);
            FIELD(thunkTo);
#undef FIELD
            snprintf(what, sizeof what, "%s.shape", a.label);
            Diff(n, what, reinterpret_cast<uintptr_t>(a.shape), reinterpret_cast<uintptr_t>(b.shape));
        }
        Diff(n, "holderCheck", t.holderCheck, f.holderCheck);
        Diff(n, "holderThunk", t.holderThunk, f.holderThunk);
        Diff(n, "sweepCall", t.sweepCall, f.sweepCall);
        Diff(n, "teleport", t.teleport, f.teleport);
        Diff(n, "teleportCall1", t.teleportCall1, f.teleportCall1);
        Diff(n, "teleportCall2", t.teleportCall2, f.teleportCall2);
        for (int i = 0; i < 2; ++i)
        {
            DiffStr(n, "other label", t.others[i].label, f.others[i].label);
            Diff(n, "other call", t.others[i].call, f.others[i].call);
        }
        Diff(n, "catchTick", t.catchTick, f.catchTick);
        Diff(n, "releaseSlot", t.releaseSlot, f.releaseSlot);
        Diff(n, "teleportHead", reinterpret_cast<uintptr_t>(t.teleportHead), reinterpret_cast<uintptr_t>(f.teleportHead));
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        printf("usage: FinderTest <patch-baseline folder>\n");
        return 2;
    }
    const std::wstring root = argv[1];
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("cannot list that folder\n");
        return 2;
    }
    int builds = 0;
    do
    {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.') continue;
        const std::wstring exe = root + L"\\" + fd.cFileName + L"\\game\\bin64\\CrimsonDesert.exe";
        std::vector<uint8_t> img;
        uint64_t imageBase = 0;
        if (!Load(exe, &img, &imageBase))
        {
            printf("%ls: no exe\n", fd.cFileName);
            continue;
        }
        ++builds;
        bt::finder::View v;
        v.base = img.data();
        v.size = img.size();
        v.loadedAt = imageBase;
        static bt::finder::Found found;
        char why[256] = "";
        const bool ok = bt::finder::Find(v, &found, why, sizeof why);
        if (!ok)
        {
            printf("%ls: the finder refused: %s (%llu ms)\n", fd.cFileName, why, found.scanMs);
            ++g_fails;
            continue;
        }
        const bt::Build* row = nullptr;
        for (const bt::Build& b : bt::kBuilds)
            if (strcmp(b.name, found.name) == 0) row = &b;
        if (!row)
        {
            printf("%ls: found version %s, which has no row\n", fd.cFileName, found.name);
            ++g_fails;
            continue;
        }
        const int before = g_fails;
        Compare(*row, found.build);
        printf("%ls: %s, %s (%llu ms)\n", fd.cFileName, found.name,
               g_fails == before ? "every field matches its row" : "MISMATCH", found.scanMs);

        // With the watchdog's guard gone, the finder has to refuse rather
        // than settle for something else.
        memset(img.data() + row->releases[3].guard, 0x90, sizeof bt::kWatchdogGuard);
        if (bt::finder::Find(v, &found, why, sizeof why))
        {
            printf("  %s: still found a row with the watchdog guard blanked\n", row->name);
            ++g_fails;
        }
        else
            printf("  with the watchdog guard blanked it refuses: %s\n", why);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    printf("%d builds, %d mismatches\n", builds, g_fails);
    return g_fails || !builds ? 1 : 0;
}
