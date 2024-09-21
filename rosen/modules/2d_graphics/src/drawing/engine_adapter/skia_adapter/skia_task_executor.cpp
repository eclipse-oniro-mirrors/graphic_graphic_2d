/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "skia_task_executor.h"
#include "utils/log.h"

#ifdef SKIA_PRIO_SCHED_ENABLE
#include "qos.h"
#endif

namespace OHOS {
namespace Rosen {

TaskPoolExecutor::TaskPoolExecutor()
{
    InitThreadPool();
}

TaskPoolExecutor& TaskPoolExecutor::GetInstance()
{
    static TaskPoolExecutor pool;
    return pool;
}

void TaskPoolExecutor::PostTask(Task&& task)
{
    GetInstance().EnqueueTask(std::move(task));
}

void TaskPoolExecutor::InitThreadPool()
{
    TaskPoolExecutor* pool = this;
    // 3 threads are created by default.
    for (uint32_t i = 0; i < DEFAULT_THREAD_COUNT; i++) {
        std::thread thread([pool, i] {
            {
                std::string name{"SkiaExecutor-"};
                name.append(std::to_string(i));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
                pthread_setname_np(name.c_str());
#else
                pthread_setname_np(pthread_self(), name.c_str());
#endif
            }
            pool->ThreadLoop();
        });
        thread.detach();
    }
}

void TaskPoolExecutor::EnqueueTask(Task&& task)
{
    std::unique_lock lock(mutex_);
    while (!taskQueue_.HasSpace()) {
        lock.unlock();
        usleep(WAIT_SLEEP_TIME);
        lock.lock();
    }
    taskQueue_.Push(std::move(task));
    if (waitingThread_ == DEFAULT_THREAD_COUNT || (waitingThread_ > 0 && taskQueue_.Size() > 1)) {
        condition_.notify_one();
    }
}

#ifdef RES_SCHED_ENABLE
void TaskPoolExecutor::PromoteThreadPriority()
{
    if (RsFrameReport::GetInstance().GetEnable()) {
        RsFrameReport::GetInstance().SetFrameParam(REQUEST_THREAD_PRIORITY_ID, REQUEST_THREAD_PRIORITY_LOAD,
            REQUEST_THREAD_PRIORITY_NUM, gettid());
    }
}
#endif

void TaskPoolExecutor::ThreadLoop()
{
#ifdef RES_SCHED_ENABLE
    PromoteThreadPriority();
#endif

#ifdef SKIA_PRIO_SCHED_ENABLE
    auto ret = OHOS::QOS::SetThreadQos(OHOS::QOS::QosLevel::QOS_USER_INTERACTIVE);
    LOGI("SkiaExecutor: SetThreadQos retcode = %{public}d", ret);
#endif
    std::unique_lock lock(mutex_);
    while (running_) {
        if (!taskQueue_.HasTask()) {
            waitingThread_++;
            condition_.wait(lock);
            waitingThread_--;
        }
        while (taskQueue_.HasTask()) {
            auto task = taskQueue_.Pop();
            lock.unlock();
            if (task != nullptr) {
                task();
            }
            lock.lock();
        }
    }
}
} // namespace Rosen
} // namespace OHOS