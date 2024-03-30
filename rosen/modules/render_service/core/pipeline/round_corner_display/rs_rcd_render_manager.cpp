/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "rs_rcd_render_manager.h"
#include "common/rs_optional_trace.h"
#include "platform/common/rs_log.h"
#include "rs_rcd_render_visitor.h"

namespace OHOS {
namespace Rosen {
static std::unique_ptr<RSRcdRenderManager> g_rcdRenderManagerInstance =
    std::make_unique<RSRcdRenderManager>();

RSRcdRenderManager& RSRcdRenderManager::GetInstance()
{
    return *g_rcdRenderManagerInstance;
}

void RSRcdRenderManager::InitInstance()
{
    g_rcdRenderManagerInstance->rcdRenderEnabled_ = true;
}

bool RSRcdRenderManager::GetRcdRenderEnabled() const
{
    return rcdRenderEnabled_;
}

void RSRcdRenderManager::DoPrepareRenderTask(const RcdProcessInfo& info)
{
    RS_LOGD("RCD: Start Do Rcd Render prepare");
    RS_TRACE_BEGIN("RSUniRender:DoRCDPrepareTask");
    if (info.topLayer == nullptr || info.bottomLayer == nullptr) {
        RS_LOGE("RCD: info toplayer or bottomlayer resource is nullptr");
        return;
    }
    auto visitor = std::make_shared<RSRcdRenderVisitor>();
    visitor->PrepareRcdSurfaceRenderNode(*bottomSurfaceNode_, info.bottomLayer, info.resourceChanged);
    visitor->PrepareRcdSurfaceRenderNode(*topSurfaceNode_, info.topLayer, info.resourceChanged);
    RS_TRACE_END();
    RS_LOGD("RCD: Finish Do Rcd Render prepare");
}

void RSRcdRenderManager::DoProcessRenderTask(std::shared_ptr<RSProcessor>& uniProcessor)
{
    RS_LOGD("RCD: Start Do Rcd Render process");
    RS_TRACE_BEGIN("RSUniRender:DoRCDProcessTask");
    if (uniProcessor == nullptr) {
        RS_LOGE("RCD: RcdProcessInfo is incorrect");
        return;
    }
    auto visitor = std::make_shared<RSRcdRenderVisitor>();
    visitor->SetUniProcessor(uniProcessor);
    visitor->ProcessRcdSurfaceRenderNode(*bottomSurfaceNode_);
    visitor->ProcessRcdSurfaceRenderNode(*topSurfaceNode_);
    RS_TRACE_END();
    RS_LOGD("RCD: Finish Do Rcd Render process");
}

void RSRcdRenderManager::Reset()
{
    topSurfaceNode_->Reset();
    bottomSurfaceNode_->Reset();
}

} // namespace Rosen
} // namespace OHOS