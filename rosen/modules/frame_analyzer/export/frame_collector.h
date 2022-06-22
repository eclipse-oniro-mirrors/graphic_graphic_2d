/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ROSEN_MODULE_FRAME_ANALYZER_EXPORT_FRAME_COLLECTOR_H
#define ROSEN_MODULE_FRAME_ANALYZER_EXPORT_FRAME_COLLECTOR_H

#include <memory>
#include <mutex>
#include <queue>

#include "frame_info.h"

namespace OHOS {
namespace Rosen {
class FrameCollector {
public:
    static FrameCollector &GetInstance();

    const std::deque<struct FrameInfo> &GetFrameQueue() const
    {
        return frameQueue_;
    }

    bool IsEnabled() const
    {
        return enabled_;
    }

    void SetEnabled(bool enable)
    {
        enabled_ = enable;
    }

    void MarkFrameEvent(const FrameEventType &type, int64_t timeNs = 0);
    void ClearEvents();

private:
    static inline std::unique_ptr<FrameCollector> instance = nullptr;

    FrameCollector();
    static void SwitchFunction(const char *key, const char *value, void *context);

    int32_t currentFrameNumber_ = 0;
    struct FrameInfo currentFrameInfo_ = {};
    std::deque<struct FrameInfo> frameQueue_;
    std::mutex frameQueueMutex_;
    bool enabled_ = false;
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_MODULE_FRAME_ANALYZER_EXPORT_FRAME_COLLECTOR_H
