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

#ifndef HGM_IDLE_DETECTOR_H
#define HGM_IDLE_DETECTOR_H

#include <string>
#include <unordered_map>
#include <vector>
#include "pipeline/rs_render_node.h"

namespace OHOS {
namespace Rosen {

enum class UIFWKType : int32_t {
    FROM_UNKNOWN = 0,
    FROM_SURFACE = 1,
};

class HgmIdleDetector {
public:
    HgmIdleDetector() = default;
    ~HgmIdleDetector() = default;

    void SetAppSupportedState(bool appSupported)
    {
        appSupported_ = appSupported;
    }

    bool GetAppSupportedState()
    {
        return appSupported_;
    }

    void SetAceAnimatorIdleState(bool aceAnimatorIdleState)
    {
        aceAnimatorIdleState_ = aceAnimatorIdleState;
    }

    bool GetAceAnimatorIdleState() const
    {
        return aceAnimatorIdleState_;
    }

    void UpdateSurfaceTime(const std::string& surfaceName, uint64_t timestamp,
        pid_t pid, UIFWKType uiFwkType = UIFWKType::FROM_UNKNOWN);
    bool GetSurfaceIdleState(uint64_t timestamp);
    int32_t GetTouchUpExpectedFPS();
    bool ThirdFrameNeedHighRefresh();
    void ClearAppBufferList()
    {
        appBufferList_.clear();
    }
    void ClearAppBufferBlackList()
    {
        appBufferBlackList_.clear();
    }
    void UpdateAppBufferList(std::vector<std::pair<std::string, int32_t>> &appBufferList)
    {
        appBufferList_ = appBufferList;
    }
    void UpdateAppBufferBlackList(std::vector<std::string> &appBufferBlackList)
    {
        appBufferBlackList_ = appBufferBlackList;
    }
    void UpdateSupportAppBufferList(std::vector<std::string> &supportAppBufferList)
    {
        supportAppBufferList_ = supportAppBufferList;
    }
    void ProcessUnknownUIFwkIdleState(const std::unordered_map<NodeId,
        std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>>>& activeNodesInRoot, uint64_t timestamp);
private:
    bool GetUnknownFrameworkState(const std::string& surfaceName);
    bool GetSurfaceFrameworkState(const std::string& surfaceName);
    bool appSupported_ = false;
    bool aceAnimatorIdleState_ = true;
    // FORMAT: <buffername>
    std::vector<std::string> appBufferBlackList_;
    std::vector<std::string> supportAppBufferList_;
    // FORMAT: <buffername, time>
    std::unordered_map<std::string, uint64_t> frameTimeMap_;
    // FORMAT: <buffername, fps>
    std::vector<std::pair<std::string, int32_t>> appBufferList_;
};
} // namespace Rosen
} // namespace OHOS
#endif // HGM_IDLE_DETECTOR_H
