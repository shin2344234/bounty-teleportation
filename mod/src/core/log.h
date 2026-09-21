#pragma once
#include <string>
#include <vector>

namespace bp::Log
{
    // printf-style. Lines are buffered until Claim(); after that they go to
    // <base>.log next to the plugin. A copy of recent lines is always kept in
    // memory either way.
    void Write(const char* level, const char* fmt, ...);

    // `base` names the file and its archives: "FlightProbe" gives
    // FlightProbe.log and FlightProbe.01.log upwards.
    //
    // It is a parameter because two processes load this plugin. Session one
    // put both of them in one file: lines from each landed at the other's file
    // offset, one was cut in half and three vanished, and the result read as
    // three hooks failing when all five had installed. Whoever is not the game
    // gets its own name and never touches the real log.
    void Claim(const wchar_t* base);

    // The same, for a log that must not accumulate: no archives, and the file
    // from last time is replaced. crashpad_handler.exe writes one line saying
    // it is doing nothing, and a history of that is worth nothing.
    void ClaimSingle(const wchar_t* base);

    // Deletes <base>.other-<pid>.log, which is what the non-game process was
    // named up to 1.1.2. Returns how many went. Only the game calls this.
    int RemovePerProcessLogs(const wchar_t* base);

    bool Claimed();

    // Marks this session's log as a trial, which takes it out of the
    // numbered rotation: at shutdown <base>.log becomes
    // <base>.trial-MMDD-HHMM-<why>.log, a name Rotate() never renames and
    // never deletes. Calling it again does nothing, so the first reason
    // wins. A note is written into the log itself as well.
    //
    // The intent is also recorded in <base>.keep next to the log, so a
    // session that crashes before Shutdown still has its log saved: the
    // next launch finds the file and does the rename before rotating.
    // Session ten's trial log, the one that answered the question, was 1.9
    // GB and went missing between two launches, which is what this is for.
    void Keep(const char* why);

    // Rotation, for the tests: false when the live log is still there and
    // could not be renamed, in which case its contents are left alone.
    bool RotateForTest(const wchar_t* base);

    // Lines are buffered (1 MB) and reach the disk on Flush(), on any error
    // line, and at Shutdown(). The mod thread calls Flush() ten times a
    // second. A flush per line cost session nine's 15:26 run the game: the
    // traced sites wrote 160,000 lines a second and each one waited on the
    // disk from the game thread, and the pickup could not complete under it.
    void Flush();
    void Shutdown();
    void Snapshot(std::vector<std::string>& out, int maxLines);
}

#define LOG(...)     ::bp::Log::Write("info ", __VA_ARGS__)
#define LOG_OK(...)  ::bp::Log::Write("ok   ", __VA_ARGS__)
#define LOG_ERR(...) ::bp::Log::Write("error", __VA_ARGS__)
