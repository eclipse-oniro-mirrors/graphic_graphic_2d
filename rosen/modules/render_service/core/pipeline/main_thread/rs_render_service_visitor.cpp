/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "pipeline/main_thread/rs_render_service_visitor.h"

#include "pipeline/render_thread/rs_divided_render_util.h"
#include "rs_trace.h"

#include "common/rs_obj_abs_geometry.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/rs_base_render_node.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_processor.h"
#include "pipeline/rs_processor_factory.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_innovation.h"
#include "platform/drawing/rs_surface.h"
#include "screen_manager/rs_screen_manager.h"
#include "screen_manager/screen_types.h"

namespace OHOS {
namespace Rosen {

RSRenderServiceVisitor::RSRenderServiceVisitor(bool parallel) : mParallelEnable(parallel) {}

RSRenderServiceVisitor::~RSRenderServiceVisitor() {}

void RSRenderServiceVisitor::PrepareChildren(RSRenderNode& node)
{
    for (auto& child : *node.GetSortedChildren()) {
        child->Prepare(shared_from_this());
    }
}

void RSRenderServiceVisitor::ProcessChildren(RSRenderNode& node)
{
    for (auto& child : *node.GetSortedChildren()) {
        child->Process(shared_from_this());
    }
}

void RSRenderServiceVisitor::PrepareDisplayRenderNode(RSDisplayRenderNode& node)
{
    isSecurityDisplay_ = node.GetSecurityDisplay();
    currentVisitDisplay_ = node.GetScreenId();
    displayHasSecSurface_.emplace(currentVisitDisplay_, false);
    sptr<RSScreenManager> screenManager = CreateOrGetScreenManager();
    if (!screenManager) {
        RS_LOGE("RSRenderServiceVisitor::PrepareDisplayRenderNode ScreenManager is nullptr");
        return;
    }
    offsetX_ = node.GetDisplayOffsetX();
    offsetY_ = node.GetDisplayOffsetY();
    ScreenInfo curScreenInfo = screenManager->QueryScreenInfo(node.GetScreenId());
    UpdateDisplayNodeCompositeType(node, curScreenInfo);
   
    ResetSurfaceNodeAttrsInDisplayNode(node);

    curDisplayNode_ = node.shared_from_this()->ReinterpretCastTo<RSDisplayRenderNode>();

    int32_t logicalScreenWidth = 0;
    int32_t logicalScreenHeight = 0;
    GetLogicalScreenSize(node, curScreenInfo, logicalScreenWidth, logicalScreenHeight);
    
    if (node.IsMirrorDisplay()) {
        auto mirrorSource = node.GetMirrorSource();
        auto existingSource = mirrorSource.lock();
        if (!existingSource) {
            RS_LOGI("RSRenderServiceVisitor::PrepareDisplayRenderNode mirrorSource haven't existed");
            return;
        }
        if (mParallelEnable) {
            CreateCanvas(logicalScreenWidth, logicalScreenHeight, true);
        }
        PrepareChildren(*existingSource);
    } else {
        auto& boundsGeoPtr = (node.GetRenderProperties().GetBoundsGeometry());
        RSBaseRenderUtil::SetNeedClient(boundsGeoPtr && boundsGeoPtr->IsNeedClientCompose());
        CreateCanvas(logicalScreenWidth, logicalScreenHeight);
        PrepareChildren(node);
    }

    node.GetCurAllSurfaces().clear();
    node.CollectSurface(node.shared_from_this(), node.GetCurAllSurfaces(), false, false);
}

void RSRenderServiceVisitor::ProcessDisplayRenderNode(RSDisplayRenderNode& node)
{
    /* need reset isSecurityDisplay_ on ProcessDisplayRenderNode */
    isSecurityDisplay_ = node.GetSecurityDisplay();
    RS_LOGD("RsDebug RSRenderServiceVisitor::ProcessDisplayRenderNode: nodeid:[%{public}" PRIu64 "]"
        " screenid:[%{public}" PRIu64 "] \
        isSecurityDisplay:[%{public}s] child size:[%{public}d]",
        node.GetId(), node.GetScreenId(), isSecurityDisplay_ ? "true" : "false", node.GetChildrenCount());
    globalZOrder_ = 0.0f;
    sptr<RSScreenManager> screenManager = CreateOrGetScreenManager();
    if (!screenManager) {
        RS_LOGE("RSRenderServiceVisitor::ProcessDisplayRenderNode ScreenManager is nullptr");
        return;
    }
    ScreenInfo curScreenInfo = screenManager->QueryScreenInfo(node.GetScreenId());
    RS_TRACE_NAME("ProcessDisplayRenderNode[" + std::to_string(node.GetScreenId()) + "]");
    RSScreenModeInfo modeInfo = {};
    screenManager->GetDefaultScreenActiveMode(modeInfo);
    uint32_t refreshRate = modeInfo.GetScreenRefreshRate();
    screenManager->RemoveForceRefreshTask();
    // skip frame according to skipFrameInterval value of SetScreenSkipFrameInterval interface
    if (node.SkipFrame(refreshRate, curScreenInfo.skipFrameInterval)) {
        RS_TRACE_NAME("SkipFrame, screenId:" + std::to_string(node.GetScreenId()));
        screenManager->PostForceRefreshTask();
        return;
    }

    curDisplayNode_ = node.shared_from_this()->ReinterpretCastTo<RSDisplayRenderNode>();

    if (!CreateProcessor(node)) {
        return;
    }

    if (node.IsMirrorDisplay()) {
        auto mirrorSource = node.GetMirrorSource();
        auto existingSource = mirrorSource.lock();
        if (!existingSource) {
            RS_LOGI("RSRenderServiceVisitor::ProcessDisplayRenderNode mirrorSource haven't existed");
            return;
        }
        if (isSecurityDisplay_ && displayHasSecSurface_[node.GetScreenId()]) {
            processor_->SetSecurityDisplay(isSecurityDisplay_);
            processor_->SetDisplayHasSecSurface(true);
            processor_->PostProcess();
            return;
        }
        ProcessChildren(*existingSource);
    } else {
        ProcessChildren(node);
    }
    for (auto& [_, funcs] : foregroundSurfaces_) {
        for (const auto& func : funcs) {
            func();
        }
    }
    foregroundSurfaces_.clear();
    processor_->PostProcess();
}

void RSRenderServiceVisitor::PrepareSurfaceRenderNode(RSSurfaceRenderNode& node)
{
    if (RSInnovation::GetParallelCompositionEnabled(false)) {
        typedef bool (*CheckForSerialForcedFunc)(std::string&);
        CheckForSerialForcedFunc CheckForSerialForced =
            reinterpret_cast<CheckForSerialForcedFunc>(RSInnovation::_s_checkForSerialForced);
        auto name = node.GetName();
        mForceSerial |= CheckForSerialForced(name);
    }

    if (isSecurityDisplay_ && node.GetSpecialLayerMgr().Find(SpecialLayerType::SECURITY)) {
        displayHasSecSurface_[currentVisitDisplay_] = true;
        RS_LOGI("RSRenderServiceVisitor::PrepareSurfaceRenderNode node : [%{public}" PRIu64 "] prepare paused \
            because of security SurfaceNode.", node.GetId());
        return;
    }
    
    if (isSecurityDisplay_ && node.GetSpecialLayerMgr().Find(SpecialLayerType::SKIP)) {
        RS_LOGD("RSRenderServiceVisitor::PrepareSurfaceRenderNode node : [%{public}" PRIu64 "] prepare paused \
            because of skip SurfaceNode.", node.GetId());
        return;
    }
    if (!canvas_) {
        RS_LOGD("RSRenderServiceVisitor::PrepareSurfaceRenderNode node : %{public}" PRIu64 " canvas is nullptr",
            node.GetId());
        return;
    }
    if (!node.ShouldPaint()) {
        RS_LOGD("RSRenderServiceVisitor::PrepareSurfaceRenderNode node : %{public}" PRIu64 " is invisible",
            node.GetId());
        return;
    }

    node.SetVisibleRegion(Occlusion::Region());
    node.SetOffset(offsetX_, offsetY_);
    node.PrepareRenderBeforeChildren(*canvas_);
    PrepareChildren(node);
    node.PrepareRenderAfterChildren(*canvas_);
    
    if (curDisplayNode_) {
        StoreSurfaceNodeAttrsToDisplayNode(*curDisplayNode_, node);
    }
}

void RSRenderServiceVisitor::ProcessSurfaceRenderNode(RSSurfaceRenderNode& node)
{
    if (!processor_) {
        RS_LOGE("RSRenderServiceVisitor::ProcessSurfaceRenderNode processor is nullptr");
        return;
    }
   
    if (curDisplayNode_) {
        RestoreSurfaceNodeAttrsFromDisplayNode(*curDisplayNode_, node);
        node.SetOffset(curDisplayNode_->GetDisplayOffsetX(), curDisplayNode_->GetDisplayOffsetY());
    }

    if (!node.ShouldPaint()) {
        RS_LOGD("RSRenderServiceVisitor::ProcessSurfaceRenderNode node : %{public}" PRIu64 " is invisible",
            node.GetId());
        return;
    }
    if (!node.GetOcclusionVisible() && !doAnimate_ && RSSystemProperties::GetOcclusionEnabled()) {
        return;
    }
    if (isSecurityDisplay_ && node.GetMultableSpecialLayerMgr().Find(SpecialLayerType::SKIP)) {
        RS_LOGD("RSRenderServiceVisitor::ProcessSurfaceRenderNode node[%{public}" PRIu64 "] process paused \
            because of skip SurfaceNode.", node.GetId());
        return;
    }
    if (mParallelEnable) {
        node.ParallelVisitLock();
    }
    ProcessChildren(node);
    auto func = [nodePtr = node.ReinterpretCastTo<RSSurfaceRenderNode>(), this]() {
        nodePtr->GetMutableRSSurfaceHandler()->SetGlobalZOrder(globalZOrder_);
        globalZOrder_ = globalZOrder_ + 1;
        processor_->ProcessSurface(*nodePtr);
    };
    if (node.GetIsForeground()) {
        auto parent = node.GetParent().lock();
        foregroundSurfaces_[parent ? parent->GetId() : 0].push_back(func);
    } else {
        func();
    }
    auto it = foregroundSurfaces_.find(node.GetId());
    if (it != foregroundSurfaces_.end()) {
        for (auto f : foregroundSurfaces_[node.GetId()]) {
            f();
        }
        foregroundSurfaces_.erase(it);
    }
    RSBaseRenderUtil::WriteSurfaceRenderNodeToPng(node);
    if (mParallelEnable) {
        node.ParallelVisitUnlock();
    }
}

void RSRenderServiceVisitor::CreateCanvas(int32_t width, int32_t height, bool isMirrored)
{
    drawingCanvas_ = std::make_unique<Drawing::Canvas>(width, height);
    canvas_ = std::make_shared<RSPaintFilterCanvas>(drawingCanvas_.get());
    Drawing::Rect tmpRect(0, 0, width, height);
    canvas_->ClipRect(tmpRect, Drawing::ClipOp::INTERSECT, false);
    if (!isMirrored) {
        Drawing::Matrix matrix;
        matrix.Translate(offsetX_ * -1, offsetY_ * -1);
        canvas_->SetMatrix(matrix);
    }
}

void RSRenderServiceVisitor::GetLogicalScreenSize(
    const RSDisplayRenderNode& node, const ScreenInfo& screenInfo, int32_t& width, int32_t& height)
{
    ScreenRotation rotation = node.GetRotation();
    width = static_cast<int32_t>(node.GetRenderProperties().GetFrameWidth());
    height = static_cast<int32_t>(node.GetRenderProperties().GetFrameHeight());
    if (width <= 0 || height <= 0) {
        width = static_cast<int32_t>(screenInfo.width);
        height = static_cast<int32_t>(screenInfo.height);

        if (rotation == ScreenRotation::ROTATION_90 || rotation == ScreenRotation::ROTATION_270) {
            std::swap(width, height);
        }
    }
}

bool RSRenderServiceVisitor::CreateProcessor(RSDisplayRenderNode& node)
{
    processor_ = RSProcessorFactory::CreateProcessor(node.GetCompositeType());
    if (processor_ == nullptr) {
        RS_LOGE("RSRenderServiceVisitor::CreateProcessor: processor_ is null!");
        return false;
    }

    auto mirrorNode = node.GetMirrorSource().lock();

    auto mainThread = RSMainThread::Instance();
    if (mainThread != nullptr) {
        processorRenderEngine_ = mainThread->GetRenderEngine();
    }

    if (!processor_->Init(node, node.GetDisplayOffsetX(), node.GetDisplayOffsetY(),
        mirrorNode ? mirrorNode->GetScreenId() : INVALID_SCREEN_ID, processorRenderEngine_)) {
        RS_LOGE("RSRenderServiceVisitor::ProcessDisplayRenderNode: processor init failed!");
        return false;
    }

    return true;
}

void RSRenderServiceVisitor::UpdateDisplayNodeCompositeType(RSDisplayRenderNode& node, const ScreenInfo& screenInfo)
{
    ScreenState state = screenInfo.state;
    switch (state) {
        case ScreenState::SOFTWARE_OUTPUT_ENABLE:
            node.SetCompositeType(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
            break;
        case ScreenState::HDI_OUTPUT_ENABLE:
            node.SetCompositeType(node.IsForceSoftComposite() ?
                RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE:
                RSDisplayRenderNode::CompositeType::HARDWARE_COMPOSITE);
            break;
        default:
            RS_LOGE("RSRenderServiceVisitor::PrepareDisplayRenderNode State is unusual");
            return;
    }
}

void RSRenderServiceVisitor::StoreSurfaceNodeAttrsToDisplayNode(
    RSDisplayRenderNode& displayNode, const RSSurfaceRenderNode& surfaceNode)
{
    displayNode.SetSurfaceSrcRect(surfaceNode.GetId(), surfaceNode.GetSrcRect());
    displayNode.SetSurfaceDstRect(surfaceNode.GetId(), surfaceNode.GetDstRect());
    displayNode.SetSurfaceTotalMatrix(surfaceNode.GetId(), surfaceNode.GetTotalMatrix());
}

void RSRenderServiceVisitor::RestoreSurfaceNodeAttrsFromDisplayNode(
    const RSDisplayRenderNode& displayNode, RSSurfaceRenderNode& surfaceNode)
{
    surfaceNode.SetSrcRect(displayNode.GetSurfaceSrcRect(surfaceNode.GetId()));
    surfaceNode.SetDstRect(displayNode.GetSurfaceDstRect(surfaceNode.GetId()));
    surfaceNode.SetTotalMatrix(displayNode.GetSurfaceTotalMatrix(surfaceNode.GetId()));
}

void RSRenderServiceVisitor::ResetSurfaceNodeAttrsInDisplayNode(RSDisplayRenderNode& displayNode)
{
    displayNode.ClearSurfaceSrcRect();
    displayNode.ClearSurfaceDstRect();
    displayNode.ClearSurfaceTotalMatrix();
}

} // namespace Rosen
} // namespace OHOS
