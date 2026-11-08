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

    // Runs of int3 padding in the code to write test stubs into, none of them
    // inside the bytes a row names.
    std::vector<uint32_t> Padding(const std::vector<uint8_t>& img, int want)
    {
        std::vector<uint32_t> out;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            img.data() + *reinterpret_cast<const uint32_t*>(img.data() + 0x3C));
        const auto* sh = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections && static_cast<int>(out.size()) < want; ++i)
        {
            if (!(sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const uint32_t end = sh[i].VirtualAddress + sh[i].Misc.VirtualSize;
            for (uint32_t r = (sh[i].VirtualAddress + 15) & ~15u;
                 r + 32 <= end && static_cast<int>(out.size()) < want; r += 16)
            {
                bool all = true;
                for (int k = 0; k < 32 && all; ++k) all = img[r + k] == 0xCC;
                if (all) out.push_back(r);
            }
        }
        return out;
    }

    void Jmp(std::vector<uint8_t>& img, uint32_t at, uint32_t to)
    {
        img[at] = 0xE9;
        const int32_t rel = static_cast<int32_t>(static_cast<int64_t>(to) - at - 5);
        memcpy(&img[at + 1], &rel, 4);
    }

    std::vector<std::string> g_notes;
    void KeepNote(const char* line) { g_notes.emplace_back(line); }

    uint32_t g_holeFrom = 0, g_holeTo = 0;
    const uint8_t* g_holeBase = nullptr;
    size_t Hole(const void* p, size_t n, bool* readable)
    {
        const uint32_t r = static_cast<uint32_t>(static_cast<const uint8_t*>(p) - g_holeBase);
        *readable = r < g_holeFrom || r >= g_holeTo;
        const uint32_t next = r < g_holeFrom ? g_holeFrom : r < g_holeTo ? g_holeTo : 0xFFFFFFFFu;
        const size_t run = next - r;
        return run < n ? run : n;
    }

    void Expect(const bt::Build& row, const char* what, const bt::finder::View& v, uint32_t slotTarget,
                uint32_t thunkTo)
    {
        static bt::finder::Found found;
        char why[256] = "";
        if (!bt::finder::Find(v, &found, why, sizeof why))
        {
            printf("  %s: %s: refused: %s\n", row.name, what, why);
            ++g_fails;
            return;
        }
        const bt::Release& a = row.releases[1];
        const bt::Release& b = found.build.releases[1];
        Diff(row.name, what, a.at, b.at);
        Diff(row.name, what, slotTarget, b.slotTarget);
        Diff(row.name, what, thunkTo, b.thunkTo);
        Diff(row.name, what, row.releases[0].at, found.build.releases[0].at);
        printf("  %s: found\n", what);
    }

    // The same exe with the client release reached some other way, the way
    // another store's link of the same version might have it.
    void Variants(bt::finder::View v, std::vector<uint8_t>& img, const bt::Build& row)
    {
        const bt::Release& cli = row.releases[1];
        const uint32_t fn = static_cast<uint32_t>(cli.thunkTo ? cli.thunkTo : cli.slotTarget);
        const uint32_t slotAt = static_cast<uint32_t>(cli.vtable + row.releaseSlot);
        const std::vector<uint32_t> pad = Padding(img, 3);
        if (pad.size() < 3)
        {
            printf("  %s: not enough padding for the variants\n", row.name);
            ++g_fails;
            return;
        }
        const uint64_t loaded = v.loadedAt;
        uint64_t slotWas;
        memcpy(&slotWas, &img[slotAt], 8);
        std::vector<uint8_t> saved[3];
        for (int i = 0; i < 3; ++i) saved[i].assign(img.begin() + pad[i], img.begin() + pad[i] + 32);
        auto restore = [&]() {
            memcpy(&img[slotAt], &slotWas, 8);
            for (int i = 0; i < 3; ++i) memcpy(&img[pad[i]], saved[i].data(), 32);
        };
        auto point = [&](uint32_t to) {
            const uint64_t q = loaded + to;
            memcpy(&img[slotAt], &q, 8);
        };

        // Two jmps in a row.
        Jmp(img, pad[0], pad[1]);
        Jmp(img, pad[1], fn);
        point(pad[0]);
        Expect(row, "a chain of two jmps", v, pad[0], fn);
        restore();

        // A second thunk to the same function, slot on the first.
        Jmp(img, pad[0], fn);
        Jmp(img, pad[1], fn);
        point(pad[0]);
        Expect(row, "two thunks to the release", v, pad[0], fn);
        restore();

        // jmp [rip+disp32] through a pointer.
        img[pad[0]] = 0xFF;
        img[pad[0] + 1] = 0x25;
        const int32_t disp = static_cast<int32_t>(static_cast<int64_t>(pad[1]) - pad[0] - 6);
        memcpy(&img[pad[0] + 2], &disp, 4);
        const uint64_t ptr = loaded + fn;
        memcpy(&img[pad[1]], &ptr, 8);
        point(pad[0]);
        Expect(row, "a jmp through a pointer", v, pad[0], fn);
        restore();

        // An adjustor thunk: sub rcx,8 / jmp.
        const uint8_t sub[4] = { 0x48, 0x83, 0xE9, 0x08 };
        memcpy(&img[pad[0]], sub, 4);
        Jmp(img, pad[0] + 4, fn);
        point(pad[0]);
        Expect(row, "an adjustor thunk", v, pad[0], fn);
        restore();

        // A loop of jmps must not hang or match.
        Jmp(img, pad[0], pad[1]);
        Jmp(img, pad[1], pad[0]);
        point(pad[0]);
        {
            static bt::finder::Found found;
            char why[256] = "";
            if (bt::finder::Find(v, &found, why, sizeof why))
            {
                printf("  %s: a loop of jmps was accepted\n", row.name);
                ++g_fails;
            }
            else
                printf("  a loop of jmps refuses: %s\n", why);
        }
        restore();

        // A page of the second code section unreadable, away from the client
        // release: 1.0.18 dropped the whole section for this.
        g_holeBase = v.base;
        g_holeFrom = (fn + 0x100000) & ~0xFFFu;
        g_holeTo = g_holeFrom + 0x1000;
        v.runs = &Hole;
        Expect(row, "an unreadable page elsewhere in the section", v,
               static_cast<uint32_t>(cli.slotTarget), static_cast<uint32_t>(cli.thunkTo));

        // The unreadable page under the client release guard. This is the
        // failure the Store build reported, with what the log then shows.
        g_holeFrom = static_cast<uint32_t>(cli.guard) & ~0xFFFu;
        g_holeTo = g_holeFrom + 0x1000;
        v.note = &KeepNote;
        g_notes.clear();
        {
            static bt::finder::Found found;
            char why[256] = "";
            if (bt::finder::Find(v, &found, why, sizeof why))
            {
                printf("  %s: found a row with the client release unreadable\n", row.name);
                ++g_fails;
            }
            else
            {
                printf("  with the client release unreadable it refuses: %s\n", why);
                if (strcmp(row.name, "1.0.0.3576") == 0)
                    for (const std::string& n : g_notes) printf("    %s\n", n.c_str());
            }
        }
        v.note = nullptr;
        v.runs = nullptr;

        // The slot pointed at something else altogether.
        point(pad[0]);
        v.note = &KeepNote;
        g_notes.clear();
        {
            static bt::finder::Found found;
            char why[256] = "";
            if (bt::finder::Find(v, &found, why, sizeof why))
            {
                printf("  %s: found a row with the slot pointing at padding\n", row.name);
                ++g_fails;
            }
            else
            {
                printf("  with the slot on padding it refuses: %s\n", why);
                if (strcmp(row.name, "1.0.0.3576") == 0)
                    for (const std::string& n : g_notes) printf("    %s\n", n.c_str());
            }
        }
        restore();
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
        Variants(v, img, *row);

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
