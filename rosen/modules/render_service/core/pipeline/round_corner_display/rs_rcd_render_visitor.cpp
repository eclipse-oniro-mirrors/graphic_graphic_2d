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

#include "rs_rcd_render_visitor.h"

#include "pipeline/rs_main_thread.h"
#include "rs_rcd_render_listener.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {
RSRcdRenderVisitor::RSRcdRenderVisitor()
{
    auto mainThread = RSMainThread::Instance();
    renderEngine_ = mainThread->GetRenderEngine();
    uniGlobalZOrder_ = static_cast<float>(0x7FFFFFFF); // make at toppest layer
}

bool RSRcdRenderVisitor::ConsumeAndUpdateBuffer(RSRcdSurfaceRenderNode& node)
{
    auto availableBufferCnt = node.GetAvailableBufferCount();
    if (availableBufferCnt <= 0) {
        // this node has no new buffer, try use old buffer.
        return true;
    }

    auto& consumer = node.GetConsumer();
    if (consumer == nullptr) {
        return false;
    }

    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> acquireFence = SyncFence::INVALID_FENCE;
    int64_t timestamp = 0;
    Rect damage;
    auto ret = consumer->AcquireBuffer(buffer, acquireFence, timestamp, damage);
    if (buffer == nullptr || ret != SURFACE_ERROR_OK) {
        RS_LOGE("RsDebug RSRcdSurfaceRenderNode(id: %{public}" PRIu64 ") AcquireBuffer failed(ret: %{public}d)!",
            node.GetNodeId(), ret);
        return false;
    }

    node.SetBuffer(buffer, acquireFence, damage, timestamp);

    if (!node.SetHardwareResourceToBuffer()) {
        RS_LOGE("RSRcdRenderVisitor SetHardwareResourceToBuffer Failed!");
        return false;
    }

    node.SetCurrentFrameBufferConsumed();
    node.ReduceAvailableBuffer();
    return true;
}

void RSRcdRenderVisitor::ProcessRcdSurfaceRenderNode(RSRcdSurfaceRenderNode& node, rs_rcd::RoundCornerLayer* layerInfo)
{
    if (uniProcessor_ == nullptr) {
        RS_LOGE("RSRcdRenderVisitor RSProcessor is null!");
        return;
    }

    if (node.IsInvalidSurface()) {
        RS_LOGE("RSRcdRenderVisitor RCDSurfaceType is NONE!");
        return;
    }

    auto surfaceNodePtr = node.ReinterpretCastTo<RSRcdSurfaceRenderNode>();
    if (!node.IsSurfaceCreated()) {
        sptr<IBufferConsumerListener> listener = new RSRcdRenderListener(surfaceNodePtr);
        if (!node.CreateSurface(listener)) {
            RS_LOGE("RSRcdRenderVisitor::RenderExpandedFrame CreateSurface failed");
            return;
        }
    }

    auto rsSurface = node.GetRSSurface();
    if (rsSurface == nullptr) {
        RS_LOGE("RSRcdRenderVisitor::RenderExpandedFrame no RSSurface found");
        return;
    }

    node.PrepareHardwareResourceBuffer(layerInfo);

#ifdef NEW_RENDER_CONTEXT
    auto renderFrame = renderEngine_->RequestFrame(std::static_pointer_cast<RSRenderSurfaceOhos>(rsSurface),
        node.GetHardenBufferRequestConfig(), true, false);
#else
    auto renderFrame = renderEngine_->RequestFrame(std::static_pointer_cast<RSSurfaceOhos>(rsSurface),
        node.GetHardenBufferRequestConfig(), true, false);
#endif
    if (renderFrame == nullptr) {
        RS_LOGE("RSRcdRenderVisitor Request Frame Failed");
        return;
    }
    renderFrame->Flush();
    if (!ConsumeAndUpdateBuffer(node)) {
        RS_LOGE("RSRcdRenderVisitor ConsumeAndUpdateBuffer Failed");
        return;
    }
    ScalingMode scalingMode = ScalingMode::SCALING_MODE_SCALE_TO_WINDOW;
    node.GetConsumer()->SetScalingMode(node.GetBuffer()->GetSeqNum(), scalingMode);

    if (node.IsTopSurface()) {
        node.SetGlobalZOrder(uniGlobalZOrder_);
    } else {
        node.SetGlobalZOrder(uniGlobalZOrder_ - 1);
    }
    uniProcessor_->ProcessRcdSurface(node);
}

void RSRcdRenderVisitor::SetUniProcessor(std::shared_ptr<RSProcessor> processor)
{
    uniProcessor_ = processor;
}
} // namespace Rosen
} // namespace OHOS