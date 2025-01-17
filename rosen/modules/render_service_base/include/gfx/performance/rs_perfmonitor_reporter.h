/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_BASE_CORE_COMMON_RS_PERFMONIYOR_LREPORTER_H
#define RENDER_SERVICE_BASE_CORE_COMMON_RS_PERFMONIYOR_LREPORTER_H

#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "utils/perfmonitor_reporter.h"
#include <ctime>
#include <mutex>
#include <map>

namespace OHOS {
namespace Rosen {

enum BLUR_CLEAR_CACHE_REASON {
    ROTATION_CHANGED = 0,
    BLUR_REGION_CHANGED,
    BLUR_CONTENT_CHANGED,
    DIRTY_OVER_SIZE,
    SKIP_FRAME_NO_VSYNC,
    NODE_IS_OCCLUDED,
    FORCE_CLEAR_CACHE,
};

class RSPerfMonitorReporter {
public:
    RSB_EXPORT static RSPerfMonitorReporter& GetInstance();

    // change bundleName when focus changed
    RSB_EXPORT void SetFocusAppInfo(const char* bundleName);

    // report except event when this frame to be end
    RSB_EXPORT void ReportAtRsFrameEnd();

    // report blur event
    void ReportBlurStatEvent();
    void ReportBlurPerfEvent();
    void ReportCacheReasonEvent();

    // report texture event
    void ReportTextureStatEvent();
    void ReportTexturePerfEvent();

    // record blur except event
    void RecordBlurPerfEvent(NodeId nodeId, const std::string& nodeName,
        uint16_t filterType, float blurRadius, int32_t width, int32_t height,
        int64_t blurTime, bool isBlurType);
    
    // record blur stats event time >= 1ms
    void RecordBlurNode(const std::string& nodeName, int64_t duration, bool isBlurType);

    // record blur cache clear reason
    void RecordBlurCacheReason(const std::string& nodeName, BLUR_CLEAR_CACHE_REASON reason,
        bool isBlurType);

    void SetCurrentBundleName(const char* bundleName);
    std::string GetCurrentBundleName();
    static bool IsOpenPerf();
private:
    std::map<std::string, std::vector<uint16_t>> statsBlur_;
    std::map<std::string, Drawing::RsBlurEvent> eventBlur_;
    std::map<std::string, std::vector<uint16_t>> statsReason_;
    std::string currentBundleName_ = "invalid";
    std::mutex mtx_;
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_CORE_COMMON_RS_PERFMONIYOR_LREPORTER_H