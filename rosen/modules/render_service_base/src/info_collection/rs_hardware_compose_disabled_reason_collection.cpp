/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "info_collection/rs_hardware_compose_disabled_reason_collection.h"

#include <cinttypes>
#include <cstdarg>

#include "common/rs_optional_trace.h"
#include "platform/common/rs_log.h"
#include "securec.h"

namespace OHOS {
namespace Rosen {
namespace {
// Buffer size for the formatted description, and for the final trace string that carries node name and id.
constexpr size_t DESC_BUF_SIZE = 512;
constexpr size_t FULL_BUF_SIZE = 1024;
} // namespace
HwcDisabledReasonCollection& HwcDisabledReasonCollection::GetInstance()
{
    static HwcDisabledReasonCollection instance;
    return instance;
}

HwcDisabledReasonCollection::HwcDisabledReasonCollection()
{
}

HwcDisabledReasonCollection::~HwcDisabledReasonCollection() noexcept
{
}

void HwcDisabledReasonCollection::UpdateHwcDisabledReasonForDFX(NodeId id,
    int32_t disabledReason, const std::string& nodeName)
{
    if (disabledReason < 0 || disabledReason >= static_cast<int32_t>(HwcDisabledReasons::DISABLED_REASON_LENGTH)) {
        RS_LOGD("HwcDisabledReasonCollection::UpdateHwcDisabledReasonForDFX disabledReason: %{public}d is invalid!",
            disabledReason);
        return;
    }
    std::lock_guard<std::mutex> lock(hwcDisabledReasonMtx_);
    auto& hwcDisabledReasonInfo = hwcDisabledReasonInfoMap_[id];
    ++hwcDisabledReasonInfo.disabledReasonStatistics[disabledReason];
    hwcDisabledReasonInfo.pidOfBelongsApp = ExtractPid(id);
    hwcDisabledReasonInfo.nodeName = nodeName;
}

// LCOV_EXCL_START
HwcDisabledReasonInfos HwcDisabledReasonCollection::GetHwcDisabledReasonInfo()
{
    std::lock_guard<std::mutex> lock(hwcDisabledReasonMtx_);
    HwcDisabledReasonInfos hwcDisabledReasonInfos;
    for (const auto& hwcDisabledReasonInfo : hwcDisabledReasonInfoMap_) {
        hwcDisabledReasonInfos.emplace_back(hwcDisabledReasonInfo.second);
    }
    hwcDisabledReasonInfoMap_.clear();
    return hwcDisabledReasonInfos;
}
// LCOV_EXCL_STOP

void HwcDisabledReasonCollection::RecordHwcDisabledWithTrace(NodeId id, int32_t disabledReason,
    const std::string& nodeName, const char* descFmt, ...)
{
    UpdateHwcDisabledReasonForDFX(id, disabledReason, nodeName);

    char descBuf[DESC_BUF_SIZE] = {0};
    char fullBuf[FULL_BUF_SIZE] = {0};

    va_list vaList;
    va_start(vaList, descFmt);
    int ret = vsnprintf_s(descBuf, sizeof(descBuf), sizeof(descBuf) - 1, descFmt, vaList);
    va_end(vaList);
    if (ret < 0) {
        RS_LOGE_LIMIT(__func__, __LINE__, "RecordHwcDisabledWithTrace vsnprintf_s desc failed, ret:%{public}d", ret);
        return;
    }

    ret = snprintf_s(fullBuf, sizeof(fullBuf), sizeof(fullBuf) - 1,
        "hwc debug: name:%s id:%" PRIu64 " %s", nodeName.c_str(), id, descBuf);
    if (ret < 0) {
        RS_LOGE_LIMIT(__func__, __LINE__, "RecordHwcDisabledWithTrace snprintf_s full failed, ret:%{public}d", ret);
        return;
    }
    RS_OPTIONAL_TRACE_FMT("%s", fullBuf);
}
} // namespace Rosen
} // namespace OHOS