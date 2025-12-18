#include <AsyncAresExecutor.h>

namespace DB {

namespace ErrorCodes
{
extern const int FAILED_SETUP;
extern const int CALLED_BEFORE_INITIALIZING_TASK_HANDLE;
extern const int TRIED_TO_DOUBLE_INITIALIZE_TASK_HANDLE;
}

/// Public methods
AsyncAresExecutor& AsyncAresExecutor::instance()
{
    static AsyncAresExecutor instance;
    return instance;
}

void AsyncAresExecutor::initialize_task_handle(ContextPtr context)
{   
    if (is_task_handle_initialized.load(std::memory_order_acquire))
        throw Exception(ErrorCodes::TRIED_TO_DOUBLE_INITIALIZE_TASK_HANDLE, "Attempted to double initialize task handle of AsyncAresExecutor");

    std::lock_guard lock{mutex};
    task_handle = context->getSchedulePool().createTask(
        "AresAsyncExecutor", 
        [this] { run(); }
    );

    is_task_handle_initialized.store(true, std::memory_order_release);
}

void AsyncAresExecutor::query(
    const char * name,
    int dnsclass,
    int type,
    ares_callback callback,
    void * arg)
{
    if (!is_task_handle_initialized.load(std::memory_order_acquire)) [[unlikely]]
        throw Exception(ErrorCodes::CALLED_BEFORE_INITIALIZING_TASK_HANDLE, "Attempted to query ares before initializing task handle in AsyncAresExecutor");

    {
        std::lock_guard lock{mutex};
        ares_query(channel, name, dnsclass, type, callback, arg);
    }

    should_process_queries.store(true, std::memory_order_release);
    if (is_allowed_to_run.load(std::memory_order_acquire))
    {
        task_handle->schedule();
    }
}

void AsyncAresExecutor::shutdown()
{
    if (task_handle)
    {
        task_handle->deactivate();
        task_handle.reset();
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
    if (is_allowed_to_run.load(std::memory_order_acquire))
    {
        /// Only run if should process queries
        /// Either way set should_process_queries to false atomically
        if (should_process_queries.exchange(false, std::memory_order_acq_rel))
        {
            {
                std::lock_guard lock{mutex};
                /// ares_process_fd handles both IO and internal timeouts
                ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
            }

            is_allowed_to_run.store(false, std::memory_order_release);
            task_handle->scheduleAfter(10);
        }
    }
    else
    {
        /// Reset state to allow it to run again after 10 ms passed
        is_allowed_to_run.store(true, std::memory_order_release);
        /// Process queries if they arrived within the idle window
        if (should_process_queries.load(std::memory_order_acquire))
        {
            task_handle->schedule();
        }
    }
}

}
