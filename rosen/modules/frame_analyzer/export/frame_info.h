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

#ifndef ROSEN_MODULE_FRAME_ANALYZER_EXPORT_FRAME_INFO_H
#define ROSEN_MODULE_FRAME_ANALYZER_EXPORT_FRAME_INFO_H

#include <array>
#include <cstdint>

namespace OHOS {
namespace Rosen {
enum class FrameEventType {
    UploadStart = 0,
    UploadEnd = 1,
    AnimateStart = 2,
    AnimateEnd = 3,
    LayoutStart = 4,
    LayoutEnd = 5,
    DrawStart = 6,
    DrawEnd = 7,
    WaitVsyncStart = 8,
    WaitVsyncEnd = 9,
    ReleaseStart = 10,
    ReleaseEnd = 11,
    FlushStart = 12,
    FlushEnd = 13,
    Max,
    LoopStart = UploadStart,
    LoopEnd = FlushEnd,
};

struct FrameInfo {
    int32_t frameNumber = 0;
    std::array<int64_t, static_cast<size_t>(FrameEventType::Max)> times = {};
};

static constexpr int32_t frameQueueMaxSize = 60;
static constexpr double frameTotalMs = 160;
static constexpr const char *switchRenderingText = "debug.graphic.frame";
static constexpr const char *switchRenderingEnableText = "true";
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_MODULE_FRAME_ANALYZER_EXPORT_FRAME_INFO_H
