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
#include "common/rs_singleton.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/round_corner_display/rs_message_bus.h"
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

void RSRcdRenderManager::DoPrepareRenderTask(const RcdPrepareInfo& info)
{
    if (!isBufferCacheClear_) {
        topSurfaceNode_->ClearBufferCache();
        bottomSurfaceNode_->ClearBufferCache();
        isBufferCacheClear_ = true;
    }
}

bool RSRcdRenderManager::IsRcdProcessInfoValid(const RcdProcessInfo& info)
{
    if (info.uniProcessor == nullptr) {
        RS_LOGE("info uniProcessor is nullptr");
        return false;
    } else if (info.topLayer == nullptr || info.bottomLayer == nullptr) {
        RS_LOGE("info toplayer or bottomlayer resource is nullptr");
        return false;
    }
    return true;
}

void RSRcdRenderManager::DoProcessRenderTask(const RcdProcessInfo& info)
{
    RS_TRACE_BEGIN("RSUniRender:DoRCDProcessTask");
    if (!IsRcdProcessInfoValid(info)) {
        RS_LOGE("RCD: RcdProcessInfo is incorrect");
        RS_TRACE_END();
        return;
    }
    auto visitor = std::make_shared<RSRcdRenderVisitor>();
    visitor->SetUniProcessor(info.uniProcessor);
    visitor->ProcessRcdSurfaceRenderNode(*bottomSurfaceNode_, info.bottomLayer, info.resourceChanged);
    visitor->ProcessRcdSurfaceRenderNode(*topSurfaceNode_, info.topLayer, info.resourceChanged);
    if (info.resourceChanged) {
        RSSingleton<RsMessageBus>::GetInstance().SendMsg<bool>(TOPIC_RCD_DISPLAY_HWRESOURCE, true);
    }
    RS_TRACE_END();
}

void RSRcdRenderManager::DoProcessRenderMainThreadTask(const RcdProcessInfo& info)
{
    RS_TRACE_BEGIN("RSUniRender:DoRCDProcessMainThreadTask");
    if (!IsRcdProcessInfoValid(info)) {
        RS_LOGE("RCD: RcdProcessInfo in MainThread is incorrect");
        RS_TRACE_END();
        return;
    }
    auto visitor = std::make_shared<RSRcdRenderVisitor>();
    visitor->SetUniProcessor(info.uniProcessor);
    visitor->ProcessRcdSurfaceRenderNodeMainThread(*bottomSurfaceNode_, info.resourceChanged);
    visitor->ProcessRcdSurfaceRenderNodeMainThread(*topSurfaceNode_, info.resourceChanged);
    RS_TRACE_END();
}

void RSRcdRenderManager::Reset()
{
    topSurfaceNode_->Reset();
    bottomSurfaceNode_->Reset();
}

} // namespace Rosen
} // namespace OHOS