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

#ifndef RENDER_SERVICE_BASE_PARAMS_RS_ROOT_RENDER_PARAMS_H
#define RENDER_SERVICE_BASE_PARAMS_RS_ROOT_RENDER_PARAMS_H

#include "params/rs_render_params.h"

namespace OHOS::Rosen {
class RSB_EXPORT RSRootRenderParams : public RSRenderParams {
public:
    explicit RSRootRenderParams(NodeId id);
    ~RSRootRenderParams() override = default;
    void OnSync(const std::unique_ptr<RSRenderParams>& target) override;

    const std::unordered_set<NodeId> GetCulledNodes() const
    {
        return std::move(culledNodes_);
    }

    bool IsOcclusionCullingOn() const
    {
        return isOcclusionCullingOn_;
    }

private:
    std::unordered_set<NodeId> culledNodes_;
    bool isOcclusionCullingOn_ = false;
    friend class RSRootRenderNode;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PARAMS_RS_ROOT_RENDER_PARAMS_H
