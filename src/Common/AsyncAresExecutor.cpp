#include <Common/AsyncAresExecutor.h>

#include <Core/BackgroundSchedulePool.h>
#include <Interpreters/Context.h>

namespace DB {

namespace ErrorCodes
{
extern const int FAILED_SETUP;
extern const int CALLED_BEFORE_INITIALIZING_TASK_HOLDER;
extern const int TRIED_TO_DOUBLE_INITIALIZE_TASK_HOLDER;
}

/// Public methods
AsyncAresExecutor& AsyncAresExecutor::instance()
{
    static AsyncAresExecutor instance;
    return instance;
}

void AsyncAresExecutor::initialize_task_holder(ContextPtr context)
{   
    if (is_task_holder_initialized.load(std::memory_order_acquire))
        throw Exception(ErrorCodes::TRIED_TO_DOUBLE_INITIALIZE_TASK_HOLDER, "Attempted to double initialize task holder of AsyncAresExecutor");

    {
        std::lock_guard lock{mutex};
        task_holder = context->getSchedulePool().createTask(
            StorageID::createEmpty(),
            "AresAsyncExecutor", 
            [this] { run(); }
        );
        task_holder->activate();
    }

    is_task_holder_initialized.store(true, std::memory_order_release);
}

void AsyncAresExecutor::query(
    const char * name,
    int dnsclass,
    int type,
    ares_callback callback,
    void * arg)
{
    if (!is_task_holder_initialized.load(std::memory_order_acquire)) [[unlikely]]
        throw Exception(ErrorCodes::CALLED_BEFORE_INITIALIZING_TASK_HOLDER, "Attempted to query ares before initializing task holder in AsyncAresExecutor");

    {
        std::lock_guard lock{mutex};
        ares_query(channel, name, dnsclass, type, callback, arg);
    }

    task_holder->schedule();
}

void AsyncAresExecutor::shutdown()
{
    if (task_holder)
    {
        task_holder->deactivate();
    }

    if (channel)
    {
        ares_destroy(channel);
        channel = nullptr;
    }
}

/// Private methods
AsyncAresExecutor::AsyncAresExecutor()
{
    /// Only use this class to init the ares library
    /// Do not init ares library multiple times within a program
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
        throw Exception(ErrorCodes::FAILED_SETUP, "Failed to initialize the c-ares library");

    if (ares_init(&channel) != ARES_SUCCESS)
    {
        ares_library_cleanup();
        throw Exception(ErrorCodes::FAILED_SETUP, "Failed to initialize the c-ares channel");
    }
}

AsyncAresExecutor::~AsyncAresExecutor()
{
    shutdown();
    ares_library_cleanup();
}

void AsyncAresExecutor::run()
{
    const UInt64 elapsed_ms = watch.elapsedMilliseconds();
    if (elapsed_ms < minimum_interval)
    {
        task_holder->scheduleAfter(minimum_interval - elapsed_ms);
        return;
    }

    {
        std::lock_guard lock{mutex};
        /// ares_process_fd handles both IO and internal timeouts
        ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }
    watch.restart();

    struct timeval tv;
    struct timeval * max_tv = nullptr; // No maximum limit
    struct timeval * next_timeout = ares_timeout(channel, max_tv, &tv);
    if (next_timeout == nullptr)
        return;

    task_holder->scheduleAfter(minimum_interval);
}

}
