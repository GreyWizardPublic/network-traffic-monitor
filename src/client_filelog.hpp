#pragma once

// client_filelog.hpp — File-based logging subsystem for ntm-client.
//
// Writes timestamped log entries to date-named files:
//   <log_dir>/ntm-client-YYYY-MM-DD.log
//
// Features:
//   - Thread-safe writes via an internal mutex.
//   - Daily rollover: a new file is opened at local midnight.
//   - 50 MB per-file cap: when a write would exceed the cap, the oldest half
//     of the file is discarded in-place (truncate-and-rewrite) before the new
//     entry is appended.  The most recent lines are always preserved.
//   - 3-day retention: files older than 3 calendar days are deleted on startup
//     and once per day at midnight (same tick as rollover).
//   - Log-level filter: entries below the current level are discarded.
//
// Lifecycle:
//   FileLogger::init()  — call once, before any log writes
//   FileLogger::write() — callable from any thread
//   FileLogger::stop()  — call on shutdown; closes the file

#include "client_platform.hpp"   // LogLevel

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace ntm
{

struct FileLogEntry
{
    platform::LogLevel level;
    std::string        message;
};

class FileLogger
{
public:
    static constexpr std::uintmax_t kMaxFileSizeBytes = 50ULL * 1024 * 1024; // 50 MB
    static constexpr int            kRetainDays        = 3;

    FileLogger() = default;
    ~FileLogger() { stop(); }

    FileLogger(const FileLogger &) = delete;
    FileLogger &operator=(const FileLogger &) = delete;

    // Open the log directory and start the first (or current) log file.
    // Returns false if the directory cannot be created or the file cannot be opened.
    bool init(const std::string &logDir, platform::LogLevel initialLevel);

    // Write a log entry. Thread-safe. No-op if init() was not called or failed.
    void write(platform::LogLevel level, const std::string &msg);

    // Close the current file. Thread-safe. No-op if already stopped.
    void stop();

    // Runtime log-level access — used by the C-line handler.
    platform::LogLevel currentLevel() const { return level_.load(std::memory_order_relaxed); }
    void setLevel(platform::LogLevel lv) { level_.store(lv, std::memory_order_relaxed); }

    // Return true if init() succeeded and logging is active.
    bool active() const { return active_; }

    // Return the log directory path (empty if not initialised).
    const std::string &logDir() const { return logDir_; }

    // List all log files with their sizes and date strings.  Thread-safe.
    struct FileInfo { std::string name; std::uintmax_t size; std::string mtime; };
    std::vector<FileInfo> listFiles() const;

    // Delete a single log file by bare filename.  Returns false if not found / error.
    bool deleteFile(const std::string &name);

    // Delete all log files (the caller is responsible for any required re-init).
    // Returns the number of files deleted.
    int deleteAllFiles();

private:
    mutable std::mutex       mtx_;
    std::string              logDir_;
    std::string              currentPath_;
    FILE                    *fp_{nullptr};
    std::uintmax_t           currentSize_{0};
    std::string              currentDateStr_;    // "YYYY-MM-DD" of the open file
    bool                     active_{false};
    std::atomic<platform::LogLevel> level_{platform::LogLevel::Info};

    // Get today's local date as "YYYY-MM-DD".
    static std::string todayDateStr();

    // Build the full path for a given date string.
    std::string pathForDate(const std::string &date) const;

    // Open (or create) the file for date, truncating if needed.
    // Returns true on success.  Caller must hold mtx_.
    bool openFile(const std::string &date);

    // Close and reset fp_/currentSize_/currentPath_.  Caller must hold mtx_.
    void closeFile();

    // Prune files older than kRetainDays.  Caller must hold mtx_.
    void pruneOldFiles();

    // Rotate in-place: discard the oldest half of the current file (line-boundary
    // aligned).  Caller must hold mtx_.
    void rotateInPlace();
};

// ---------------------------------------------------------------------------
// Global singleton accessor — one per process.
// ---------------------------------------------------------------------------

FileLogger &globalFileLogger();

} // namespace ntm
