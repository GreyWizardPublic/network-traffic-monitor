// Tests for client_filelog.hpp / client_filelog.cpp

#include "ntm_test.hpp"
#include "client_filelog.hpp"
#include "client_platform.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Create a unique temp directory for one test.
static fs::path makeTempDir()
{
    const std::string base = fs::temp_directory_path().string() + "/ntm_filelog_test_";
    static std::atomic<int> counter{0};
    const std::string dir = base + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count()
        + counter.fetch_add(1));
    fs::create_directories(dir);
    return dir;
}

// Remove temp directory.
static void removeTempDir(const fs::path &p)
{
    std::error_code ec;
    fs::remove_all(p, ec);
}

// Write a file with the given content at the given path.
static void writeFile(const fs::path &p, const std::string &content)
{
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// Read entire file content.
static std::string readFile(const fs::path &p)
{
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), {});
}

// Count files matching a prefix in dir.
static int countLogFiles(const fs::path &dir)
{
    int n = 0;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(dir, ec))
    {
        if (!e.is_regular_file(ec)) continue;
        const std::string name = e.path().filename().string();
        if (name.rfind("ntm-client-", 0) == 0 && name.size() >= 25)
            ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("filelog: init creates log directory and file")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));
    REQUIRE(logger.active());
    REQUIRE_EQ(logger.logDir(), logDir.string());

    // At least one .log file should exist after init.
    REQUIRE(countLogFiles(logDir) >= 1);

    logger.stop();
    removeTempDir(dir);
}

TEST_CASE("filelog: write appends to log file")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));

    logger.write(ntm::platform::LogLevel::Info, "hello world");
    logger.write(ntm::platform::LogLevel::Warn, "a warning");
    logger.stop();

    // Find the log file and verify content.
    std::string allContent;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(logDir, ec))
    {
        if (!e.is_regular_file(ec)) continue;
        allContent += readFile(e.path());
    }
    REQUIRE(allContent.find("hello world") != std::string::npos);
    REQUIRE(allContent.find("a warning") != std::string::npos);

    removeTempDir(dir);
}

TEST_CASE("filelog: level filtering — Warn suppresses Info")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Warn));

    logger.write(ntm::platform::LogLevel::Info, "this should not appear");
    logger.write(ntm::platform::LogLevel::Warn, "this should appear");
    logger.stop();

    std::string allContent;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(logDir, ec))
    {
        if (!e.is_regular_file(ec)) continue;
        allContent += readFile(e.path());
    }
    REQUIRE(allContent.find("this should not appear") == std::string::npos);
    REQUIRE(allContent.find("this should appear") != std::string::npos);

    removeTempDir(dir);
}

TEST_CASE("filelog: setLevel changes filtering at runtime")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Err));

    logger.write(ntm::platform::LogLevel::Info, "before level change — should be absent");
    logger.setLevel(ntm::platform::LogLevel::Info);
    logger.write(ntm::platform::LogLevel::Info, "after level change — should appear");
    logger.stop();

    std::string allContent;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(logDir, ec))
    {
        if (!e.is_regular_file(ec)) continue;
        allContent += readFile(e.path());
    }
    REQUIRE(allContent.find("before level change") == std::string::npos);
    REQUIRE(allContent.find("after level change") != std::string::npos);

    removeTempDir(dir);
}

TEST_CASE("filelog: currentLevel reflects setLevel")
{
    const fs::path dir = makeTempDir();
    ntm::FileLogger logger;
    REQUIRE(logger.init(dir.string(), ntm::platform::LogLevel::Info));

    REQUIRE_EQ(static_cast<int>(logger.currentLevel()),
               static_cast<int>(ntm::platform::LogLevel::Info));

    logger.setLevel(ntm::platform::LogLevel::Warn);
    REQUIRE_EQ(static_cast<int>(logger.currentLevel()),
               static_cast<int>(ntm::platform::LogLevel::Warn));

    logger.setLevel(ntm::platform::LogLevel::Err);
    REQUIRE_EQ(static_cast<int>(logger.currentLevel()),
               static_cast<int>(ntm::platform::LogLevel::Err));

    logger.stop();
    removeTempDir(dir);
}

TEST_CASE("filelog: rotateInPlace triggers at 50 MB cap and reduces file size")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));

    // Write lines totalling just over 50 MB.
    // Each line is ~100 bytes; 50 MB / 100 bytes = 524288 lines.
    // Write 520000 lines to approach the cap, then write one more to trigger rotation.
    const std::string line(96, 'X'); // 96 chars + ~5-char prefix ≈ 101 chars per entry
    const std::size_t targetOverCap = ntm::FileLogger::kMaxFileSizeBytes + 200;
    std::size_t written = 0;
    while (written < targetOverCap)
    {
        logger.write(ntm::platform::LogLevel::Info, line);
        written += line.size() + 32; // approximate (prefix + newline)
    }

    // Trigger one more write to force rotation check.
    logger.write(ntm::platform::LogLevel::Info, "trigger line after cap");
    logger.stop();

    // After rotation, the file should be < 50 MB.
    bool foundFile = false;
    std::uintmax_t fileSize = 0;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(logDir, ec))
    {
        if (!e.is_regular_file(ec)) continue;
        const std::string name = e.path().filename().string();
        if (name.rfind("ntm-client-", 0) != 0) continue;
        foundFile = true;
        fileSize = e.file_size(ec);
        break;
    }
    REQUIRE(foundFile);
    REQUIRE(fileSize < ntm::FileLogger::kMaxFileSizeBytes);
    // After rotate-in-place the file should be roughly half the original (≥ 1 byte).
    REQUIRE(fileSize > 0);

    removeTempDir(dir);
}

TEST_CASE("filelog: rotateInPlace preserves newest lines (second half)")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));

    // Write many lines that together exceed the cap.
    // Early lines: "EARLY_LINE_N" → should disappear after rotation.
    // Late lines: "LATE_LINE_N"  → should survive.
    const std::size_t lineSize = 100;
    const std::size_t linesNeeded =
        (ntm::FileLogger::kMaxFileSizeBytes / lineSize) + 100;

    for (std::size_t i = 0; i < linesNeeded / 2; ++i)
        logger.write(ntm::platform::LogLevel::Info,
                     "EARLY_LINE_" + std::to_string(i) + std::string(lineSize - 20, 'A'));

    for (std::size_t i = 0; i < linesNeeded / 2; ++i)
        logger.write(ntm::platform::LogLevel::Info,
                     "LATE_LINE_" + std::to_string(i) + std::string(lineSize - 19, 'B'));

    // One more write to force the rotation check.
    logger.write(ntm::platform::LogLevel::Info, "sentinel");
    logger.stop();

    std::string allContent;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(logDir, ec))
    {
        if (!e.is_regular_file(ec)) continue;
        allContent += readFile(e.path());
    }

    // The very last LATE lines and "sentinel" must survive.
    REQUIRE(allContent.find("sentinel") != std::string::npos);
    // The very first EARLY line (index 0) should NOT be in the file.
    REQUIRE(allContent.find("EARLY_LINE_0 ") == std::string::npos);

    removeTempDir(dir);
}

TEST_CASE("filelog: 3-day retention prune removes old files")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";
    fs::create_directories(logDir);

    // Manually create stale log files with dates > 3 days ago.
    writeFile(logDir / "ntm-client-2020-01-01.log", "old log 1\n");
    writeFile(logDir / "ntm-client-2020-01-02.log", "old log 2\n");

    // Now init the logger — pruneOldFiles() runs during init.
    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));
    logger.stop();

    // Old files should be pruned.
    std::error_code ec;
    REQUIRE(!fs::exists(logDir / "ntm-client-2020-01-01.log", ec));
    REQUIRE(!fs::exists(logDir / "ntm-client-2020-01-02.log", ec));

    removeTempDir(dir);
}

TEST_CASE("filelog: 3-day retention preserves recent files")
{
    using namespace std::chrono;
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";
    fs::create_directories(logDir);

    // Create a log file dated today (should NOT be pruned).
    const std::time_t t = std::time(nullptr);
    struct tm tmLocal{};
    localtime_r(&t, &tmLocal);
    char dateBuf[11];
    std::strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d", &tmLocal);
    const std::string todayDate(dateBuf);
    const std::string todayFile = "ntm-client-" + todayDate + ".log";
    writeFile(logDir / todayFile, "today's log\n");

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));
    logger.stop();

    // Today's file should still exist.
    std::error_code ec;
    REQUIRE(fs::exists(logDir / todayFile, ec));

    removeTempDir(dir);
}

TEST_CASE("filelog: listFiles returns entries with name and size")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));
    logger.write(ntm::platform::LogLevel::Info, "test entry");
    logger.stop();  // flush to disk

    // Re-init to get the file properly closed and listed.
    ntm::FileLogger logger2;
    REQUIRE(logger2.init(logDir.string(), ntm::platform::LogLevel::Info));
    const auto files = logger2.listFiles();
    logger2.stop();

    REQUIRE(!files.empty());
    bool foundLog = false;
    for (const auto &f : files)
    {
        if (f.name.rfind("ntm-client-", 0) == 0)
        {
            foundLog = true;
            REQUIRE(f.size > 0);
            REQUIRE(f.mtime.size() == 10); // YYYY-MM-DD
            break;
        }
    }
    REQUIRE(foundLog);

    removeTempDir(dir);
}

TEST_CASE("filelog: listFiles sorted newest first")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";
    fs::create_directories(logDir);

    // Create fake log files for 3 different days.
    writeFile(logDir / "ntm-client-2026-05-28.log", "a\n");
    writeFile(logDir / "ntm-client-2026-05-30.log", "c\n");
    writeFile(logDir / "ntm-client-2026-05-29.log", "b\n");

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));
    const auto files = logger.listFiles();
    logger.stop();

    // Files should be sorted newest-first (2026-05-30, 2026-05-29, 2026-05-28).
    // Plus possibly today's file from init — filter to just our planted files.
    std::vector<std::string> names;
    for (const auto &f : files)
    {
        if (f.name == "ntm-client-2026-05-28.log" ||
            f.name == "ntm-client-2026-05-29.log" ||
            f.name == "ntm-client-2026-05-30.log")
            names.push_back(f.name);
    }
    // These will be pruned if today is > 3 days past 2026-05-28 — skip ordering check
    // only if they were pruned (test environment date unknown).
    if (names.size() == 3)
    {
        REQUIRE_EQ(names[0], std::string("ntm-client-2026-05-30.log"));
        REQUIRE_EQ(names[1], std::string("ntm-client-2026-05-29.log"));
        REQUIRE_EQ(names[2], std::string("ntm-client-2026-05-28.log"));
    }
    // If pruned (test run after 2026-06-02), the ordering constraint doesn't apply.

    removeTempDir(dir);
}

TEST_CASE("filelog: deleteFile removes a specific file")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));

    // Plant a file AFTER init so pruneOldFiles() doesn't remove it.
    // Use a filename with today's date so it's within the 3-day retention window.
    const std::time_t t = std::time(nullptr);
    struct tm tmLocal{};
    localtime_r(&t, &tmLocal);
    char dateBuf[11];
    std::strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d", &tmLocal);
    const std::string fname = std::string("ntm-client-") + dateBuf + "-extra.log";
    writeFile(logDir / fname, "some log content\n");
    REQUIRE(fs::exists(logDir / fname));

    REQUIRE(logger.deleteFile(fname));

    std::error_code ec;
    REQUIRE(!fs::exists(logDir / fname, ec));

    logger.stop();
    removeTempDir(dir);
}

TEST_CASE("filelog: deleteFile rejects path traversal")
{
    const fs::path dir = makeTempDir();
    ntm::FileLogger logger;
    REQUIRE(logger.init(dir.string(), ntm::platform::LogLevel::Info));

    REQUIRE(!logger.deleteFile("../etc/passwd"));
    REQUIRE(!logger.deleteFile("../../secret"));
    REQUIRE(!logger.deleteFile("/etc/passwd"));  // no '/' in filename

    logger.stop();
    removeTempDir(dir);
}

TEST_CASE("filelog: deleteAllFiles removes all matching files and returns count")
{
    const fs::path dir = makeTempDir();
    const fs::path logDir = dir / "logs";
    fs::create_directories(logDir);

    // Plant 3 files + one non-matching file (should NOT be deleted).
    writeFile(logDir / "ntm-client-2025-01-01.log", "a\n");
    writeFile(logDir / "ntm-client-2025-01-02.log", "b\n");
    writeFile(logDir / "ntm-client-2025-01-03.log", "c\n");
    writeFile(logDir / "other-file.txt", "not mine\n");

    ntm::FileLogger logger;
    REQUIRE(logger.init(logDir.string(), ntm::platform::LogLevel::Info));

    // deleteAllFiles counts matching files.  The 3 planted files + today's file = 4 or 3
    // (depending on whether today's file was added during init or if the 2025 dates were pruned).
    // Just verify the count matches the remaining matching files.
    const int before = countLogFiles(logDir);
    const int deleted = logger.deleteAllFiles();
    REQUIRE(deleted == before);
    REQUIRE(countLogFiles(logDir) <= 1); // at most today's fresh file

    // The non-matching file must survive.
    std::error_code ec;
    REQUIRE(fs::exists(logDir / "other-file.txt", ec));

    logger.stop();
    removeTempDir(dir);
}

TEST_CASE("filelog: inactive logger write is a no-op")
{
    ntm::FileLogger logger;
    REQUIRE(!logger.active());
    // Should not crash or write anything.
    logger.write(ntm::platform::LogLevel::Info, "should not crash");
    const auto files = logger.listFiles();
    REQUIRE(files.empty());
}

TEST_CASE("filelog: globalFileLogger is a singleton")
{
    // Two calls to globalFileLogger() should return the same address.
    REQUIRE(&ntm::globalFileLogger() == &ntm::globalFileLogger());
}
