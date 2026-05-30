#include "client_filelog.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

namespace ntm
{

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string levelToStr(platform::LogLevel lv)
{
    switch (lv)
    {
    case platform::LogLevel::Info: return "INFO";
    case platform::LogLevel::Warn: return "WARN";
    case platform::LogLevel::Err:  return "ERR ";
    }
    return "????";
}

// ---------------------------------------------------------------------------
// FileLogger public interface
// ---------------------------------------------------------------------------

bool FileLogger::init(const std::string &logDir, platform::LogLevel initialLevel)
{
    std::lock_guard<std::mutex> lk(mtx_);
    logDir_ = logDir;
    level_.store(initialLevel, std::memory_order_relaxed);

    // Create directory if it does not exist.
    std::error_code ec;
    std::filesystem::create_directories(logDir_, ec);
    if (ec)
        return false;

    pruneOldFiles();

    const std::string today = todayDateStr();
    if (!openFile(today))
        return false;

    active_ = true;
    return true;
}

void FileLogger::write(platform::LogLevel level, const std::string &msg)
{
    if (!active_) return;
    if (static_cast<int>(level) < static_cast<int>(level_.load(std::memory_order_relaxed)))
        return;

    // Build the log line: "[YYYY-MM-DD HH:MM:SS LEVEL] msg\n"
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    char timeBuf[32];
    struct tm tmLocal{};
#ifdef _WIN32
    localtime_s(&tmLocal, &t);
#else
    localtime_r(&t, &tmLocal);
#endif
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmLocal);

    char dateBuf[11];
    std::strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d", &tmLocal);
    const std::string dateStr(dateBuf);

    // Build the line before acquiring the lock to reduce lock hold time.
    std::string line = "[";
    line += timeBuf;
    line += ' ';
    line += levelToStr(level);
    line += "] ";
    line += msg;
    if (line.empty() || line.back() != '\n')
        line += '\n';

    std::lock_guard<std::mutex> lk(mtx_);
    if (!fp_) return;

    // Daily rollover: new day → close old file, prune old files, open new one.
    if (dateStr != currentDateStr_)
    {
        closeFile();
        pruneOldFiles();
        if (!openFile(dateStr))
            return;
    }

    // Size cap: if adding this line would push the file over kMaxFileSizeBytes,
    // discard the oldest half first.
    if (currentSize_ + line.size() > kMaxFileSizeBytes)
        rotateInPlace();

    if (!fp_) return;

    const std::size_t written = std::fwrite(line.data(), 1, line.size(), fp_);
    if (written > 0)
    {
        currentSize_ += written;
        std::fflush(fp_);
    }
}

void FileLogger::stop()
{
    std::lock_guard<std::mutex> lk(mtx_);
    active_ = false;
    closeFile();
}

std::vector<FileLogger::FileInfo> FileLogger::listFiles() const
{
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<FileInfo> result;
    if (logDir_.empty()) return result;

    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(logDir_, ec))
    {
        if (!entry.is_regular_file(ec)) continue;
        const std::string name = entry.path().filename().string();
        // Only list files that match our naming convention.
        if (name.rfind("ntm-client-", 0) != 0) continue;
        if (name.size() < 11 || name.substr(name.size() - 4) != ".log") continue;

        FileInfo fi;
        fi.name = name;
        fi.size = entry.file_size(ec);
        if (ec) fi.size = 0;

        // Extract date from filename: ntm-client-YYYY-MM-DD.log
        if (name.size() >= 21)
            fi.mtime = name.substr(11, 10); // "YYYY-MM-DD"
        else
            fi.mtime = "unknown";

        result.push_back(fi);
    }

    // Sort newest first (lexicographic on YYYY-MM-DD in filename works correctly).
    std::sort(result.begin(), result.end(),
              [](const FileInfo &a, const FileInfo &b) { return a.name > b.name; });
    return result;
}

bool FileLogger::deleteFile(const std::string &name)
{
    // Validate name: no path separators, must match our prefix.
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos)
        return false;
    if (name.rfind("ntm-client-", 0) != 0 || name.size() < 12) return false;

    std::lock_guard<std::mutex> lk(mtx_);
    if (logDir_.empty()) return false;

    const std::string path = logDir_ + "/" + name;

    // If this is the currently open file, close it first so the OS flushes.
    if (path == currentPath_)
        closeFile();

    std::error_code ec;
    return std::filesystem::remove(path, ec) && !ec;
}

int FileLogger::deleteAllFiles()
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (logDir_.empty()) return 0;

    // Close current file so its bytes are flushed before we delete it.
    closeFile();

    int count = 0;
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(logDir_, ec))
    {
        if (!entry.is_regular_file(ec)) continue;
        const std::string name = entry.path().filename().string();
        if (name.rfind("ntm-client-", 0) != 0) continue;
        if (name.size() < 11 || name.substr(name.size() - 4) != ".log") continue;
        if (std::filesystem::remove(entry.path(), ec))
            ++count;
    }

    // Reopen a fresh file for today so subsequent writes work.
    if (active_)
        openFile(todayDateStr());

    return count;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

std::string FileLogger::todayDateStr()
{
    const std::time_t t = std::time(nullptr);
    struct tm tmLocal{};
#ifdef _WIN32
    localtime_s(&tmLocal, &t);
#else
    localtime_r(&t, &tmLocal);
#endif
    char buf[11];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmLocal);
    return buf;
}

std::string FileLogger::pathForDate(const std::string &date) const
{
    return logDir_ + "/ntm-client-" + date + ".log";
}

bool FileLogger::openFile(const std::string &date)
{
    const std::string path = pathForDate(date);
    fp_ = std::fopen(path.c_str(), "a");
    if (!fp_) return false;

    // Measure existing size so we know where we stand on the cap.
    std::error_code ec;
    currentSize_ = std::filesystem::file_size(path, ec);
    if (ec) currentSize_ = 0;

    currentPath_    = path;
    currentDateStr_ = date;
    return true;
}

void FileLogger::closeFile()
{
    if (fp_) { std::fclose(fp_); fp_ = nullptr; }
    currentPath_.clear();
    currentDateStr_.clear();
    currentSize_ = 0;
}

void FileLogger::pruneOldFiles()
{
    if (logDir_.empty()) return;

    // Compute the cutoff date (kRetainDays days ago).
    const std::time_t now = std::time(nullptr);
    const std::time_t cutoff = now - static_cast<std::time_t>(kRetainDays) * 86400;
    struct tm cutoffTm{};
#ifdef _WIN32
    localtime_s(&cutoffTm, &cutoff);
#else
    localtime_r(&cutoff, &cutoffTm);
#endif
    char cutoffBuf[11];
    std::strftime(cutoffBuf, sizeof(cutoffBuf), "%Y-%m-%d", &cutoffTm);
    const std::string cutoffDate(cutoffBuf);

    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(logDir_, ec))
    {
        if (!entry.is_regular_file(ec)) continue;
        const std::string name = entry.path().filename().string();
        if (name.rfind("ntm-client-", 0) != 0) continue;
        // Extract date portion: ntm-client-YYYY-MM-DD.log → positions 11..20
        if (name.size() < 25) continue; // "ntm-client-YYYY-MM-DD.log" = 25 chars
        const std::string fileDate = name.substr(11, 10);
        if (fileDate < cutoffDate)
            std::filesystem::remove(entry.path(), ec);
    }
}

void FileLogger::rotateInPlace()
{
    // Read the whole file, find the midpoint on a line boundary, then rewrite
    // with only the second half.  This preserves the most recent log entries.
    if (!fp_ || currentPath_.empty()) return;

    std::fflush(fp_);
    std::fclose(fp_);
    fp_ = nullptr;

    // Read entire file.
    FILE *f = std::fopen(currentPath_.c_str(), "rb");
    if (!f)
    {
        openFile(currentDateStr_);
        return;
    }
    std::fseek(f, 0, SEEK_END);
    const long fileLen = std::ftell(f);
    if (fileLen <= 0)
    {
        std::fclose(f);
        openFile(currentDateStr_);
        return;
    }
    std::rewind(f);
    std::vector<char> buf(static_cast<std::size_t>(fileLen));
    const std::size_t rd = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);

    // Find a newline at or after the midpoint.
    const std::size_t mid = rd / 2;
    std::size_t keepFrom = mid;
    while (keepFrom < rd && buf[keepFrom] != '\n')
        ++keepFrom;
    if (keepFrom < rd)
        ++keepFrom; // skip past the '\n'

    // Rewrite the file with only the kept portion.
    FILE *fw = std::fopen(currentPath_.c_str(), "wb");
    if (fw)
    {
        if (keepFrom < rd)
            std::fwrite(buf.data() + keepFrom, 1, rd - keepFrom, fw);
        std::fclose(fw);
    }

    // Reopen for append.
    fp_ = std::fopen(currentPath_.c_str(), "a");
    if (fp_)
    {
        std::error_code ec;
        currentSize_ = std::filesystem::file_size(currentPath_, ec);
        if (ec) currentSize_ = 0;
    }
    else
    {
        currentSize_ = 0;
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

FileLogger &globalFileLogger()
{
    static FileLogger instance;
    return instance;
}

} // namespace ntm
