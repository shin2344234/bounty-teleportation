#include "core/log.h"

#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <deque>
#include <mutex>

#include "core/paths.h"

namespace bp::Log
{
    static std::mutex               g_mu;
    static std::deque<std::string>  g_recent;   // for the Status tab
    static std::deque<std::string>  g_pending;  // not yet on disk
    static FILE*                    g_file    = nullptr;
    static bool                     g_claimed = false;
    static std::wstring             g_base;      // "BountyProbe"
    static std::wstring             g_keepAs;    // the trial name, once Keep() has run
    static constexpr size_t         kKeep     = 400;

    static std::string Stamp()
    {
        SYSTEMTIME t;
        GetLocalTime(&t);
        char b[32];
        snprintf(b, sizeof b, "%02d:%02d:%02d.%03d", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
        return b;
    }

    void Write(const char* level, const char* fmt, ...)
    {
        char msg[2048];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof msg, fmt, ap);
        va_end(ap);

        std::string line = "[" + Stamp() + "] [" + level + "] " + msg;

        std::lock_guard<std::mutex> lk(g_mu);
        g_recent.push_back(line);
        if (g_recent.size() > kKeep) g_recent.pop_front();
        if (g_file)
        {
            fputs(line.c_str(), g_file);
            fputc('\n', g_file);
            if (level[0] == 'e') fflush(g_file);
        }
        else
        {
            g_pending.push_back(line);
            if (g_pending.size() > kKeep) g_pending.pop_front();
        }
    }

    // Keep the last dozen sessions instead of one. The whole point of this
    // plugin is the log it leaves, and a probe run is usually worth comparing
    // against the one before it: the town flight and the mountain flight are
    // two sessions, not one. Lifted from Master Looter, where a launch that
    // destroyed the previous log cost a capture that had answered something.
    //
    // Plain text, not compressed. These get pasted into a message, and an
    // archive is a barrier to that.
    static constexpr int kArchives = 24;   // plus the live one. Sessions are cheap; losing one is not.

    // <base>.keep holds the trial name of a log whose session did not get to
    // rename it, as a plain wide string. Written when Keep() is called and
    // removed as soon as the rename happens, either at shutdown or here.
    static void KeepFileName(const wchar_t* base, wchar_t* out, size_t cap)
    {
        _snwprintf_s(out, cap, _TRUNCATE, L"%s.keep", base);
    }

    static bool ReadPendingKeep(const wchar_t* base, wchar_t* out, size_t cap)
    {
        wchar_t sentinel[96];
        KeepFileName(base, sentinel, _countof(sentinel));
        FILE* f = _wfopen(Paths::File(sentinel).c_str(), L"rb");
        if (!f) return false;
        const size_t n = fread(out, sizeof(wchar_t), cap - 1, f);
        fclose(f);
        out[n] = 0;
        return n > 0 && wcsstr(out, L".log") != nullptr;
    }

    static void ClearPendingKeep(const wchar_t* base)
    {
        wchar_t sentinel[96];
        KeepFileName(base, sentinel, _countof(sentinel));
        DeleteFileW(Paths::File(sentinel).c_str());
    }

    // False when the live log is still there and could not be renamed, which
    // means the caller must not open it for writing.
    static bool Rotate(const wchar_t* base)
    {
        wchar_t from[96], to[96], live[96];
        _snwprintf_s(live, _countof(live), _TRUNCATE, L"%s.log", base);

        // A trial whose session never reached Shutdown: take its log out of
        // the rotation now, before anything shifts, and let this session
        // start a fresh <base>.log.
        wchar_t pending[128];
        if (ReadPendingKeep(base, pending, _countof(pending)))
        {
            if (MoveFileExW(Paths::File(live).c_str(), Paths::File(pending).c_str(), MOVEFILE_REPLACE_EXISTING))
                Write("ok   ", "[log] the last session was a trial and did not close cleanly, so its log was "
                               "kept as %ls instead of being rotated", pending);
            ClearPendingKeep(base);
        }
        // Oldest out first, then each one shuffles up a place, so the numbers
        // read as age: 01 is the session before this one, 11 the furthest back.
        _snwprintf_s(to, _countof(to), _TRUNCATE, L"%s.%02d.log", base, kArchives);
        DeleteFileW(Paths::File(to).c_str());
        for (int i = kArchives - 1; i >= 1; --i)
        {
            _snwprintf_s(from, _countof(from), _TRUNCATE, L"%s.%02d.log", base, i);
            _snwprintf_s(to,   _countof(to),   _TRUNCATE, L"%s.%02d.log", base, i + 1);
            MoveFileExW(Paths::File(from).c_str(), Paths::File(to).c_str(), MOVEFILE_REPLACE_EXISTING);
        }
        // The last session's log becomes .01. This is the step that failed
        // on 20 September 2026: the game was restarted twice within three
        // minutes, the exiting process still held its 1.9 GB log open, the
        // rename lost to a sharing violation, and the fresh fopen(L"w")
        // emptied the file. A trial log went that way. So: wait for the old
        // process to let go, and say so when it does not.
        _snwprintf_s(to, _countof(to), _TRUNCATE, L"%s.01.log", base);
        const std::wstring liveP = Paths::File(live), toP = Paths::File(to);
        if (GetFileAttributesW(liveP.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
        for (int attempt = 0; attempt < 10; ++attempt)
        {
            if (MoveFileExW(liveP.c_str(), toP.c_str(), MOVEFILE_REPLACE_EXISTING)) return true;
            Sleep(100);
        }
        return false;
    }

    // Caller holds g_mu. `append` keeps what is already in the file, for the
    // case where rotation could not move it out of the way.
    static void Open(const wchar_t* base, bool append = false)
    {
        wchar_t live[96];
        _snwprintf_s(live, _countof(live), _TRUNCATE, L"%s.log", base);
        g_file = _wfopen(Paths::File(live).c_str(), append ? L"a" : L"w");
        if (!g_file) return;
        setvbuf(g_file, nullptr, _IOFBF, 1 << 20);
        for (const auto& l : g_pending)
        {
            fputs(l.c_str(), g_file);
            fputc('\n', g_file);
        }
        g_pending.clear();
        fflush(g_file);
    }

    void Claim(const wchar_t* base)
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_claimed) return;
        g_claimed = true;
        g_base = base;
        const bool rotated = Rotate(base);
        if (!rotated)
            Write("error", "[log] the last session's log could not be renamed after a second of trying, so it is "
                           "still open somewhere. This session appends to it rather than emptying it; both "
                           "sessions are in one file and the header lines mark the join.");
        Open(base, !rotated);
    }

    void ClaimSingle(const wchar_t* base)
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_claimed) return;
        g_claimed = true;
        g_base = base;
        Open(base);
    }

    bool RotateForTest(const wchar_t* base) { return Rotate(base); }

    void Keep(const char* why)
    {
        wchar_t name[128], tag[24] = L"";
        {
            std::lock_guard<std::mutex> lk(g_mu);
            if (!g_keepAs.empty() || g_base.empty()) return;

            // Letters and digits of `why`, at most sixteen, so the reason
            // survives into the file name without anything a path minds.
            size_t k = 0;
            for (const char* p = why; p && *p && k < 16; ++p)
                if (isalnum(static_cast<unsigned char>(*p))) tag[k++] = static_cast<wchar_t>(*p);
            tag[k] = 0;

            SYSTEMTIME t;
            GetLocalTime(&t);
            _snwprintf_s(name, _countof(name), _TRUNCATE, L"%s.trial-%02d%02d-%02d%02d%s%s.log",
                         g_base.c_str(), t.wMonth, t.wDay, t.wHour, t.wMinute, tag[0] ? L"-" : L"", tag);
            g_keepAs = name;

            wchar_t sentinel[96];
            KeepFileName(g_base.c_str(), sentinel, _countof(sentinel));
            if (FILE* f = _wfopen(Paths::File(sentinel).c_str(), L"wb"))
            {
                fwrite(name, sizeof(wchar_t), wcslen(name), f);
                fclose(f);
            }
        }
        Write("ok   ", "[log] this session is a trial (%s), so its log is kept as %ls when the game closes and "
                       "never enters the numbered rotation", why ? why : "?", name);
    }

    // Up to 1.1.2 the non-game process named its log after its own process id,
    // so every crashpad_handler.exe that ever started left a file behind and
    // nothing removed them. One bin64 had 78 of them, one line each. The name
    // is fixed now, and this clears out what the old builds left.
    //
    // A wildcard can match a file through its 8.3 short name, so the name that
    // comes back is checked against the pattern again before anything goes.
    // Nothing outside <base>.other-*.log is ever deleted.
    int RemovePerProcessLogs(const wchar_t* base)
    {
        wchar_t prefix[96], pattern[96];
        _snwprintf_s(prefix,  _countof(prefix),  _TRUNCATE, L"%s.other-", base);
        _snwprintf_s(pattern, _countof(pattern), _TRUNCATE, L"%s*.log", prefix);

        WIN32_FIND_DATAW fd;
        const HANDLE h = FindFirstFileW(Paths::File(pattern).c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return 0;

        const size_t plen = wcslen(prefix);
        int removed = 0;
        do
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            const size_t n = wcslen(fd.cFileName);
            if (n <= plen + 4) continue;
            if (_wcsnicmp(fd.cFileName, prefix, plen) != 0) continue;
            if (_wcsicmp(fd.cFileName + n - 4, L".log") != 0) continue;
            if (DeleteFileW(Paths::File(fd.cFileName).c_str())) ++removed;
        } while (FindNextFileW(h, &fd));

        FindClose(h);
        return removed;
    }

    bool Claimed()
    {
        std::lock_guard<std::mutex> lk(g_mu);
        return g_claimed;
    }

    void Flush()
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_file) fflush(g_file);
    }

    void Shutdown()
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_file) { fclose(g_file); g_file = nullptr; }
        if (g_keepAs.empty() || g_base.empty()) return;

        wchar_t live[96];
        _snwprintf_s(live, _countof(live), _TRUNCATE, L"%s.log", g_base.c_str());
        MoveFileExW(Paths::File(live).c_str(), Paths::File(g_keepAs.c_str()).c_str(), MOVEFILE_REPLACE_EXISTING);
        ClearPendingKeep(g_base.c_str());
        g_keepAs.clear();
    }

    void Snapshot(std::vector<std::string>& out, int maxLines)
    {
        std::lock_guard<std::mutex> lk(g_mu);
        out.clear();
        const size_t n = g_recent.size();
        const size_t start = (maxLines > 0 && n > static_cast<size_t>(maxLines)) ? n - maxLines : 0;
        for (size_t i = start; i < n; ++i) out.push_back(g_recent[i]);
    }
}
