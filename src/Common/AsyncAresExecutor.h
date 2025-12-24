#pragma once

#include <ares.h>

#include <atomic>


namespace DB
{

/**
 * @brief A thread-safe wrapper for the c-ares asynchronous resolver library.
 *
 * This singleton ensures that:
 * 1. The library and its internal channel are initialized once and cleaned up on exit.
 * 2. Asynchronous requests can be safely submitted from any thread.
 * 3. Request processing (ares_process) is handled automatically in the background,
 *    respecting a 10ms minimum interval to optimize resource usage.
 */
class AsyncAresExecutor {
public:
    AsyncAresExecutor(const AsyncAresExecutor&) = delete;
    AsyncAresExecutor& operator=(const AsyncAresExecutor&) = delete;
    AsyncAresExecutor(AsyncAresExecutor &&) = delete;
    AsyncAresExecutor& operator=(AsyncAresExecutor &&) = delete;
    
    static AsyncAresExecutor& instance();
    void query(const char *, int, int, ares_callback, void *);
    void shutdown();

private:
    AsyncAresExecutor();
    ~AsyncAresExecutor();

    void loop();

    ares_channel channel{nullptr};
    std::atomic<bool> is_shutdown_called{false};
};

}
