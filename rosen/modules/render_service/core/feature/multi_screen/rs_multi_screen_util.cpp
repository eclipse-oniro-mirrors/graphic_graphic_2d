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

#include "rs_multi_screen_util.h"

#include <algorithm>
#include <climits>
#include <cmath>

#include "common/rs_optional_trace.h"
#include "drawable/dfx/rs_dirty_rects_dfx.h"
#include "drawable/rs_logical_display_render_node_drawable.h"
#include "drawable/rs_render_node_drawable.h"
#include "drawable/rs_screen_render_node_drawable.h"
#include "feature/dirty/rs_uni_dirty_compute_util.h"
#include "feature/drm/rs_drm_util.h"
#include "feature/frame_stability/rs_frame_stability_manager.h"
#include "feature/special_layer/rs_special_layer_utils.h"
#include "feature/pointer_window_manager/rs_pointer_window_manager.h"
#include "graphic_feature_param_manager.h"
#include "params/rs_render_thread_params.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "pipeline/render_thread/rs_uni_render_virtual_processor.h"
#include "pipeline/render_thread/rs_virtual_screen_parallel_manager.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "rs_profiler_capture_recorder.h"
#include "rs_trace.h"
#include "surface.h"
#include "system/rs_system_parameters.h"

namespace OHOS::Rosen::DrawableV2 {

void RSMultiScreenUtil::HandleMirrorDisplay(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (!uniParam) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_THREAD_PARAMS_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s uniParam is null", __func__);
        return;
    }

    auto [_, screenParams] = drawable.GetScreenParams(params);
    if (!screenParams) {
        RS_LOGE("RSMultiScreenUtil::%{public}s screenParams is null", __func__);
        return;
    }

    if (!processor || !processor->UpdateMirrorInfo(drawable)) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_ENGINE_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s processor update info failed", __func__);
        return;
    }

    const auto& screenProperty = screenParams->GetScreenProperty();
    uniParam->SetSecurityDisplay(params.IsSecurityDisplay());
    drawable.currentBlackList_ = RSSpecialLayerUtils::GetMergeBlackListInRenderThread(screenProperty);
    RSUniRenderThread::Instance().SetBlackList(drawable.currentBlackList_);
    drawable.curVisibleRect_ = RSUniRenderThread::Instance().GetVisibleRect();
    drawable.enableVisibleRect_ = RSUniRenderThread::Instance().GetEnableVisibleRect();

    if (params.GetCompositeType() == CompositeType::UNI_RENDER_COMPOSITE) {
        RSMultiScreenUtil::DrawPhysicalMirrorDisplay(drawable, params, processor);
        drawable.lastBlackList_ = drawable.currentBlackList_;
        drawable.lastEnableVisibleRect_ = drawable.enableVisibleRect_;
        drawable.lastVisibleRect_ = drawable.curVisibleRect_;
        uniParam->SetSecurityDisplay(false);
        RSUniRenderThread::Instance().SetBlackList({});
        return;
    }

    drawable.currentTypeBlackList_ = screenProperty.GetTypeBlackList();
    RSUniRenderThread::Instance().SetTypeBlackList(drawable.currentTypeBlackList_);
    RSUniRenderThread::Instance().SetWhiteList(screenParams->GetEffectiveWhiteList());
    drawable.curSecExemption_ = params.GetSecurityExemption();
    uniParam->SetSecExemption(drawable.curSecExemption_);

    RSMultiScreenUtil::DrawVirtualMirrorDisplay(drawable, params, processor);

    drawable.lastEnableVisibleRect_ = drawable.enableVisibleRect_;
    drawable.lastVisibleRect_ = drawable.curVisibleRect_;
    drawable.lastTypeBlackList_ = drawable.currentTypeBlackList_;
    drawable.lastSecExemption_ = drawable.curSecExemption_;
    uniParam->SetSecurityDisplay(false);
    drawable.lastBlackList_ = drawable.currentBlackList_;
    RSUniRenderThread::Instance().SetBlackList({});
    RSUniRenderThread::Instance().SetTypeBlackList({});
    RSUniRenderThread::Instance().SetWhiteList({});
    uniParam->SetSecExemption(false);
}

void RSMultiScreenUtil::HandleVirtualExtendDisplay(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (!uniParam) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_THREAD_PARAMS_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s uniParam is null", __func__);
        return;
    }

    auto [_, screenParams] = drawable.GetScreenParams(params);
    if (!screenParams) {
        RS_LOGE("RSMultiScreenUtil::%{public}s screenParams is null", __func__);
        return;
    }

    auto virtualProcessor = RSProcessor::ReinterpretCast<RSUniRenderVirtualProcessor>(processor);
    if (!virtualProcessor) {
        RS_LOGE("RSMultiScreenUtil::%{public}s virtualProcessor is nullptr", __func__);
        return;
    }

    if (!virtualProcessor->UpdateMirrorInfo(drawable)) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_ENGINE_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s processor update info failed", __func__);
        return;
    }

    const auto& screenProperty = screenParams->GetScreenProperty();
    uniParam->SetSecurityDisplay(params.IsSecurityDisplay());
    drawable.currentBlackList_ = RSSpecialLayerUtils::GetMergeBlackListInRenderThread(screenProperty);
    RSUniRenderThread::Instance().SetBlackList(drawable.currentBlackList_);
    RSUniRenderThread::Instance().SetTypeBlackList(screenProperty.GetTypeBlackList());
    RSUniRenderThread::Instance().SetWhiteList(screenParams->GetEffectiveWhiteList());
    drawable.curSecExemption_ = params.GetSecurityExemption();
    uniParam->SetSecExemption(drawable.curSecExemption_);

    RSMultiScreenUtil::DrawVirtualExtend(drawable, params, virtualProcessor);

    drawable.lastSecExemption_ = drawable.curSecExemption_;
    uniParam->SetSecurityDisplay(false);
    drawable.lastBlackList_ = drawable.currentBlackList_;
    RSUniRenderThread::Instance().SetBlackList({});
    RSUniRenderThread::Instance().SetTypeBlackList({});
    RSUniRenderThread::Instance().SetWhiteList({});
    uniParam->SetSecExemption(false);
}

void RSMultiScreenUtil::HandleMirrorScreen(
    RSScreenRenderNodeDrawable& drawable,
    RSScreenRenderParams& mirrorSourceParams,
    RSScreenRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (!uniParam) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_PARAMS_OR_UNI_PARAMS_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s uniParam is null!", __func__);
        return;
    }

    const auto& screenProperty = params.GetScreenProperty();

    RSUniRenderThread::BufferManagerGuard bufferGuard;
    DirtyStatusAutoUpdate dirtyStatusAutoUpdate(*uniParam, params.GetChildDisplayCount() == 1);
    if (!processor || !processor->InitForRenderThread(drawable, RSUniRenderThread::Instance().GetRenderEngine())) {
        // Clear cacheImgForCapture so that mirrorScreen avoid using an expired cache
        drawable.cacheImgForCapture_ = nullptr;
        drawable.SetDrawSkipType(DrawSkipType::RENDER_ENGINE_NULL);
        drawable.syncDirtyManager_->ResetDirtyAsSurfaceSize();
        drawable.syncDirtyManager_->UpdateDirty(false);
        RS_LOGD("RSMultiScreenUtil::%{public}s processor init for render thread failed!", __func__);
        return;
    }

    const auto& mirrorSourceProperty = mirrorSourceParams.GetScreenProperty();
    drawable.offsetX_ = mirrorSourceProperty.GetOffsetX();
    drawable.offsetY_ = mirrorSourceProperty.GetOffsetY();
    bool enableVisibleRect = screenProperty.GetEnableVisibleRect();
    RSUniRenderThread::Instance().SetEnableVisibleRect(enableVisibleRect);
    if (enableVisibleRect) {
        const auto& rect = screenProperty.GetVisibleRect();
        auto curVisibleRect = Drawing::RectI(rect.x, rect.y, rect.x + rect.w, rect.y + rect.h);
        RSUniRenderThread::Instance().SetVisibleRect(curVisibleRect);
    }

    if (params.GetCompositeType() == CompositeType::UNI_RENDER_COMPOSITE) {
        drawable.SetDrawSkipType(DrawSkipType::WIRED_SCREEN_PROJECTION);
        RSUniRenderThread::Instance().WaitUntilScreenNodeBufferReleased(drawable);
        drawable.physicalMirrorRenderFrame_ = drawable.RequestFrame(params, processor);
        if (!drawable.physicalMirrorRenderFrame_) {
            drawable.SetDrawSkipType(DrawSkipType::REQUEST_FRAME_FAIL);
            RS_LOGE("RSMultiScreenUtil::%{public}s failed to request frame", __func__);
            return;
        }
        auto drSurface = drawable.physicalMirrorRenderFrame_->GetFrame()->GetSurface();
        if (!drSurface) {
            RS_LOGE("RSMultiScreenUtil::%{public}s DrawingSurface is null", __func__);
            return;
        }
        drawable.curCanvas_ = std::make_shared<RSPaintFilterCanvas>(drSurface.get());
        drawable.RSRenderNodeDrawable::OnDraw(*drawable.curCanvas_);
        drawable.physicalMirrorRenderFrame_->Flush();
        processor->ProcessScreenSurfaceForRenderThread(drawable);
        RSPointerWindowManager::Instance().HardCursorCreateLayer(processor, drawable.GetId());
        processor->PostProcess();
        bufferGuard.SetAcquireFence(drawable.physicalMirrorRenderFrame_->GetAcquireFence());
        drawable.physicalMirrorRenderFrame_ = nullptr;
        return;
    }

    auto virtualProcessor = RSProcessor::ReinterpretCast<RSUniRenderVirtualProcessor>(processor);
    if (!virtualProcessor) {
        RS_LOGE("RSMultiScreenUtil::%{public}s virtualProcessor is null!", __func__);
        return;
    }
    drawable.curCanvas_ = virtualProcessor->GetCanvas();
    drawable.RSRenderNodeDrawable::OnDraw(*drawable.curCanvas_);
    if (virtualProcessor->GetDisplaySkipInMirror()) {
        RS_TRACE_NAME("skip in virtual screen and cancelbuffer");
        virtualProcessor->SetDisplaySkipInMirror(false);
        virtualProcessor->CancelCurrentFrame();
        return;
    }
    drawable.DrawCurtainScreen();
    processor->PostProcess();
    bufferGuard.SetAcquireFence(virtualProcessor->GetFrameAcquireFence());
    drawable.SetDrawSkipType(DrawSkipType::MIRROR_DRAWABLE_SKIP);
}

void RSMultiScreenUtil::HandleVirtualExtendScreen(
    RSScreenRenderNodeDrawable& drawable,
    RSScreenRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor,
    std::shared_ptr<RSBaseRenderEngine> renderEngine,
    int32_t tid)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (!uniParam) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_PARAMS_OR_UNI_PARAMS_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s uniParam is null!", __func__);
        return;
    }

    const auto& screenProperty = params.GetScreenProperty();
    auto screenInfo = screenProperty.GetScreenInfo();
    ScreenId paramScreenId = params.GetScreenId();

    RSUniRenderThread::BufferManagerGuard bufferGuard;
    DirtyStatusAutoUpdate dirtyStatusAutoUpdate(*uniParam, params.GetChildDisplayCount() == 1);
    if (!renderEngine) {
        renderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    }
    if (!processor || !processor->InitForRenderThread(drawable, renderEngine, tid)) {
        // Clear cacheImgForCapture so that mirrorScreen avoid using an expired cache
        drawable.cacheImgForCapture_ = nullptr;
        drawable.SetDrawSkipType(DrawSkipType::RENDER_ENGINE_NULL);
        drawable.syncDirtyManager_->ResetDirtyAsSurfaceSize();
        drawable.syncDirtyManager_->UpdateDirty(false);
        RS_LOGD("RSMultiScreenUtil::%{public}s processor init for render thread failed!", __func__);
        return;
    }

    RS_LOGD("RSMultiScreenUtil::%{public}s Expand screen.", __func__);
    bool isOpDropped = uniParam->IsOpDropped();
    auto expandProcessor = RSProcessor::ReinterpretCast<RSUniRenderVirtualProcessor>(processor);
    if (!expandProcessor) {
        drawable.SetDrawSkipType(DrawSkipType::EXPAND_PROCESSOR_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s expandProcessor is null!", __func__);
        return;
    }
    bool isVirtualExtendScreenDirty = uniParam->IsVirtualExpandScreenDirtyEnabled() &&
        !uniParam->IsVirtualDirtyDfxEnabled();
    uniParam->SetOpDropped(isVirtualExtendScreenDirty && !expandProcessor->IsMultiSurfaceExtendMode());
    RSDirtyRectsDfx rsDirtyRectsDfx(drawable);
    std::vector<RectI> damageRegionRects;
    RSUniDirtyComputeUtil::MergeVirtualExpandScreenAccumulatedDirtyRegions(drawable, params);
    int32_t bufferAge = expandProcessor->GetBufferAge();
    damageRegionRects = RSUniRenderUtil::MergeDirtyHistory(
        drawable, bufferAge, screenInfo, rsDirtyRectsDfx, params);
    uniParam->Reset();
    if (isVirtualExtendScreenDirty && !expandProcessor->IsMultiSurfaceExtendMode()) {
        expandProcessor->SetDirtyInfo(damageRegionRects);
    } else {
        std::vector<RectI> emptyRects = {};
        expandProcessor->SetRoiRegionToCodec(emptyRects);
    }

    // record current frame refresh area to frame stability manager
    std::vector<RectI> refreshRects(damageRegionRects);
    refreshRects.emplace_back(drawable.syncDirtyManager_->GetHwcDirtyRegion());
    RSFrameStabilityManager::GetInstance().RecordCurrentFrameDirty(
        paramScreenId, refreshRects, screenInfo.width * screenInfo.height);

    rsDirtyRectsDfx.SetVirtualDirtyRects(damageRegionRects, screenInfo);
    drawable.curCanvas_ = expandProcessor->GetCanvas();
    auto& curCanvas = drawable.curCanvas_;
    curCanvas->Save();
    if (isVirtualExtendScreenDirty && !expandProcessor->IsMultiSurfaceExtendMode()) {
        drawable.UpdateSurfaceDrawRegion(curCanvas, &params);
        curCanvas->SetDrawnRegion(params.GetDrawnRegion());
        if (uniParam->IsDirtyAlignEnabled() && RSUniDirtyComputeUtil::IsDamageRegionGpuTileValid() &&
            damageRegionRects.size() > RSUniDirtyComputeUtil::DIRTY_REGION_COUNT_THRESHOLD) {
            RS_TRACE_NAME("dirty align enabled and no clip operation");
            curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);
        } else {
            Drawing::Region clipRegion = RSUniDirtyComputeUtil::GetFlippedRegion(damageRegionRects, screenInfo);
            RSUniDirtyComputeUtil::ClipRegion(*curCanvas, clipRegion);
        }
    } else {
        curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);
    }
    RSUniDirtyComputeUtil::ClearVirtualExpandScreenAccumulatedDirtyRegions(drawable, params);
    drawable.RSRenderNodeDrawable::OnDraw(*curCanvas);
    params.ResetVirtualExpandAccumulatedParams();
    RSUniRenderThread::ResetCaptureParam();
    auto targetSurfaceRenderNodeDrawable = std::static_pointer_cast<RSSurfaceRenderNodeDrawable>(
        params.GetTargetSurfaceRenderNodeDrawable().lock());
    // Sometimes may require setting cacheImg, such as MultiScreenView and SingleAppCast
    if ((targetSurfaceRenderNodeDrawable || params.HasMirrorScreen()) && curCanvas->GetSurface()) {
        RS_TRACE_NAME_FMT("%s set cacheImg for capture or multiscreenview", __func__);
        drawable.cacheImgForCapture_ = curCanvas->GetSurface()->GetImageSnapshot();
        drawable.cacheImgForMultiScreenView_ = drawable.cacheImgForCapture_;
    } else {
        drawable.cacheImgForCapture_ = nullptr;
        drawable.cacheImgForMultiScreenView_ = nullptr;
    }
    // Restore the initial state of the canvas to avoid state accumulation
    curCanvas->RestoreToCount(0);
    if (curCanvas) {
        rsDirtyRectsDfx.OnDrawVirtual(*curCanvas);
    }
    uniParam->SetOpDropped(isOpDropped);
    drawable.DrawCurtainScreen();
    processor->PostProcess();
    drawable.SetFirstFrameFlushed(true);
    bufferGuard.SetAcquireFence(expandProcessor->GetFrameAcquireFence());
    drawable.SetDrawSkipType(DrawSkipType::MIRROR_DRAWABLE_SKIP);
}

void RSMultiScreenUtil::DrawPhysicalMirrorDisplay(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    auto& curCanvas = drawable.curCanvas_;
    if (!curCanvas) {
        RS_LOGE("RSMultiScreenUtil::%{public}s failed to create canvas", __func__);
        return;
    }

    auto [multiScreenParams, isValid] = RSMultiScreenUtil::GetMultiScreenParams(params);
    if (!isValid) {
        RS_LOGE("RSMultiScreenUtil::%{public}s params are invalid", __func__);
        return;
    }

    auto& [screenDrawable, screenParams, mirrorSourceDisplayDrawable, mirrorSourceDisplayParams,
        mirrorSourceScreenDrawable, mirrorSourceScreenParams] = multiScreenParams;
    auto cacheImage = mirrorSourceScreenDrawable->GetCacheImgForCapture();
    const auto& specialLayerMgr = mirrorSourceDisplayParams->GetSpecialLayerMgr();
    bool needProcessSecLayer = !MultiScreenParam::IsExternalScreenSecure() &&
        specialLayerMgr.Find(SpecialLayerType::HAS_SECURITY);
    const auto& currentBlackList = drawable.currentBlackList_;
    bool hasProtected = specialLayerMgr.Find(SpecialLayerType::HAS_PROTECTED);
    bool hasSpecialLayer = mirrorSourceScreenParams->GetHDRPresent() || needProcessSecLayer ||
        !currentBlackList.empty() || hasProtected;
    bool enableVisibleRect = drawable.enableVisibleRect_;
    bool isRedraw = RSSystemParameters::GetDebugMirrorOndrawEnabled() || !cacheImage ||
        (RSSystemParameters::GetWiredScreenOndrawEnabled() && !enableVisibleRect && hasSpecialLayer);

    RS_TRACE_NAME_FMT("%s, cacheImage[%d], enableVisibleRect[%d], mirroredHDR[%d], needProcessSecLayer[%d], "
        "blackListSize[%zu], hasProtected[%d]",
        __func__, cacheImage != nullptr, enableVisibleRect, mirrorSourceScreenParams->GetHDRPresent(),
        needProcessSecLayer, currentBlackList.size(), hasProtected);

    // HDR does not support wired screen
    if (isRedraw) {
        drawable.isMirrorSLRCopy_ = false;
        RSMultiScreenUtil::DumpRenderStrategy(drawable, params.GetScreenId(),
            RenderStrategy::DRAW_PHYSICAL_MIRROR_REBUILD, "");
        RSMultiScreenUtil::DrawPhysicalMirrorRebuild(drawable, params, processor);
    } else {
        // cacheImage must be valid when isMirrorSLRCopy_ is true
        drawable.isMirrorSLRCopy_ = !enableVisibleRect && RSSystemProperties::GetSLRScaleEnabled();
        RSMultiScreenUtil::DumpRenderStrategy(drawable, params.GetScreenId(),
            RenderStrategy::DRAW_PHYSICAL_MIRROR_FROM_CACHE, "");
        RSMultiScreenUtil::DrawPhysicalMirrorFromCache(drawable, params);
    }
}

void RSMultiScreenUtil::DrawPhysicalMirrorFromCache(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params)
{
    auto [multiScreenParams, isValid] = RSMultiScreenUtil::GetMultiScreenParams(params);
    if (!isValid) {
        RS_LOGE("RSMultiScreenUtil::%{public}s params are invalid", __func__);
        return;
    }

    auto& [screenDrawable, screenParams, mirrorSourceDisplayDrawable, mirrorSourceDisplayParams,
        mirrorSourceScreenDrawable, mirrorSourceScreenParams] = multiScreenParams;

    auto& curCanvas = drawable.curCanvas_;
    curCanvas->Save();
    curCanvas->SetOnMultipleScreen(true); // use for hdr content tmo to fixed sdr nits
    drawable.ScaleAndRotateMirrorForWiredScreen(*mirrorSourceDisplayDrawable);
    RSDirtyRectsDfx rsDirtyRectsDfx(*screenDrawable);
    std::shared_ptr<RSSLRScaleFunction> scaleManager = drawable.scaleManager_;
    auto matrix = drawable.isMirrorSLRCopy_ ? scaleManager->GetScaleMatrix() : curCanvas->GetTotalMatrix();
    matrix.PreTranslate(-mirrorSourceDisplayParams->GetOffsetX(), -mirrorSourceDisplayParams->GetOffsetY());
    std::vector<RectI> damageRegionRects = drawable.CalculateVirtualDirtyForWiredScreen(*screenDrawable, matrix);
    rsDirtyRectsDfx.SetVirtualDirtyRects(damageRegionRects, screenParams->GetScreenInfo());

    auto width = mirrorSourceDisplayParams->GetFixedWidth();
    auto height = mirrorSourceDisplayParams->GetFixedHeight();

    auto cacheImage = mirrorSourceScreenDrawable->GetCacheImgForCapture();
    bool enableVisibleRect = drawable.enableVisibleRect_;
    const auto& curVisibleRect = drawable.curVisibleRect_;

    // Hardware-enabled nodes are composed as separate layers on the mirror source screen, so
    // neither the cache image nor the display surface contains their content. Draw them below
    // the frame content (which has transparent holes at their positions) and the top ones above
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hwcNodes;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hwcTopNodes;
    RSUniRenderUtil::CollectHardwareEnabledNodesByDisplayNodeId(hwcNodes, hwcTopNodes,
        mirrorSourceDisplayDrawable->GetId());

    curCanvas->Save();
    if (drawable.isMirrorSLRCopy_ && scaleManager) {
        auto scaleNum = scaleManager->GetScaleNum();
        curCanvas->Scale(scaleNum, scaleNum);
    }
    if (!enableVisibleRect) {
        // layer matrices are absolute in the source screen render frame; shift the canvas origin
        // from source display logical space to screen space, same as DrawPhysicalMirrorRebuild.
        // Visible-rect mode needs no shift: layer matrices are mapped inside
        // RSUniRenderUtil::AdjustZOrderAndDrawSurfaceNode.
        curCanvas->Translate(-mirrorSourceDisplayParams->GetOffsetX(), -mirrorSourceDisplayParams->GetOffsetY());
    }
    RSUniRenderUtil::AdjustZOrderAndDrawSurfaceNode(hwcNodes, *curCanvas, *mirrorSourceScreenParams);
    curCanvas->Restore();

    if (cacheImage && RSSystemProperties::GetDrawMirrorCacheImageEnabled()) {
        RS_TRACE_NAME_FMT("%s, use cacheImage, hwcNodes[%zu], hwcTopNodes[%zu], scaleManager[%d]", __func__,
            hwcNodes.size(), hwcTopNodes.size(), scaleManager != nullptr);
        if (drawable.isMirrorSLRCopy_) {
            RS_TRACE_NAME_FMT("%s, use SLRScale", __func__);
            scaleManager->ProcessCacheImage(*curCanvas, *cacheImage);
        } else if (!enableVisibleRect) {
            RS_TRACE_NAME_FMT("%s, use SkiaScale", __func__);
            Drawing::RectI srcRect = { mirrorSourceDisplayParams->GetOffsetX(), mirrorSourceDisplayParams->GetOffsetY(),
                mirrorSourceDisplayParams->GetOffsetX() + width, mirrorSourceDisplayParams->GetOffsetY() + height };
            RSUniRenderUtil::ProcessCacheImageRect(*curCanvas, *cacheImage, srcRect,
                Drawing::Rect(0, 0, width, height));
        } else {
            RS_TRACE_NAME_FMT("%s, visibleRect[%d, %d, %d, %d]", __func__,
                curVisibleRect.GetLeft(), curVisibleRect.GetTop(),
                curVisibleRect.GetWidth(), curVisibleRect.GetHeight());
            RSUniRenderUtil::ProcessCacheImageRect(*curCanvas, *cacheImage, curVisibleRect,
                Drawing::Rect(0, 0, curVisibleRect.GetWidth(), curVisibleRect.GetHeight()));
        }
    } else {
        RS_TRACE_NAME_FMT("%s, use displaySurface, hwcNodes[%zu], hwcTopNodes[%zu], scaleManager[%d]", __func__,
            hwcNodes.size(), hwcTopNodes.size(), scaleManager != nullptr);
        auto surfaceHandler = mirrorSourceScreenDrawable->GetRSSurfaceHandlerOnDraw();
        auto drawParams = RSUniRenderUtil::CreateBufferDrawParam(*surfaceHandler, false); // false: draw with gpu
        auto renderEngine = RSUniRenderThread::Instance().GetRenderEngine();
        if (enableVisibleRect) {
            drawParams.srcRect = curVisibleRect;
            drawParams.dstRect = Drawing::Rect(0, 0, curVisibleRect.GetWidth(), curVisibleRect.GetHeight());
        } else {
            drawParams.srcRect = { mirrorSourceDisplayParams->GetOffsetX(), mirrorSourceDisplayParams->GetOffsetY(),
                mirrorSourceDisplayParams->GetOffsetX() + width, mirrorSourceDisplayParams->GetOffsetY() + height };
            drawParams.dstRect = Drawing::Rect(0, 0, width, height);
        }
        drawParams.isMirror = true;
        renderEngine->DrawScreenNodeWithParams(*curCanvas, *surfaceHandler, drawParams);
        RSMainThread::Instance()->RequestNextVSync();
    }

    curCanvas->Save();
    if (drawable.isMirrorSLRCopy_ && scaleManager) {
        auto scaleNum = scaleManager->GetScaleNum();
        curCanvas->Scale(scaleNum, scaleNum);
    }
    if (!enableVisibleRect) {
        // layer matrices are absolute in the source screen render frame; shift the canvas origin
        // from source display logical space to screen space, same as DrawPhysicalMirrorRebuild.
        // Visible-rect mode needs no shift: layer matrices are mapped inside
        // RSUniRenderUtil::AdjustZOrderAndDrawSurfaceNode.
        curCanvas->Translate(-mirrorSourceDisplayParams->GetOffsetX(), -mirrorSourceDisplayParams->GetOffsetY());
    }
    // exclude hard cursor of source screen, because physical mirror screen has its own hard cursor
    hwcTopNodes.erase(std::remove_if(hwcTopNodes.begin(), hwcTopNodes.end(), [](const auto& adapter) {
        auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(adapter);
        return surfaceDrawable && surfaceDrawable->IsHardwareEnabledTopSurface();
        }), hwcTopNodes.end());
    RSUniRenderUtil::AdjustZOrderAndDrawSurfaceNode(hwcTopNodes, *curCanvas, *mirrorSourceScreenParams);
    curCanvas->Restore();

    curCanvas->Restore();
    rsDirtyRectsDfx.OnDrawVirtual(*curCanvas);
}

void RSMultiScreenUtil::DrawPhysicalMirrorRebuild(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (uniParam == nullptr) {
        RS_LOGE("RSMultiScreenUtil::%{public}s uniParam is null", __func__);
        return;
    }
    auto [multiScreenParams, isValid] = RSMultiScreenUtil::GetMultiScreenParams(params);
    if (!isValid) {
        RS_LOGE("RSMultiScreenUtil::%{public}s params are invalid", __func__);
        return;
    }

    auto& [screenDrawable, screenParams, mirrorSourceDisplayDrawable, mirrorSourceDisplayParams,
        mirrorSourceScreenDrawable, mirrorSourceScreenParams] = multiScreenParams;

    RS_TRACE_FUNC();
    RSDirtyRectsDfx rsDirtyRectsDfx(*screenDrawable);

    // for HDR
    auto& curCanvas = drawable.curCanvas_;
    curCanvas->SetOnMultipleScreen(true);
    curCanvas->SetDisableFilterCache(true);

    // Draw security mask if has security surface and external screen is not secure
    const auto& specialLayerMgr = mirrorSourceDisplayParams->GetSpecialLayerMgr();
    auto hasSecSurface = specialLayerMgr.Find(SpecialLayerType::HAS_SECURITY);
    if (hasSecSurface && !MultiScreenParam::IsExternalScreenSecure()) {
        drawable.DrawSecurityMask();
        drawable.virtualDirtyNeedRefresh_ = true;
        rsDirtyRectsDfx.OnDrawVirtual(*curCanvas);
        return;
    }

    curCanvas->Save();
    drawable.ScaleAndRotateMirrorForWiredScreen(*mirrorSourceDisplayDrawable);
    Drawing::Matrix canvasMatrix = curCanvas->GetTotalMatrix();
    curCanvas->SetHighContrast(RSUniRenderThread::Instance().IsHighContrastTextModeOn());
    bool isOpDropped = uniParam->IsOpDropped();
    uniParam->SetOpDropped(false);
    auto screenInfo = mirrorSourceScreenParams->GetScreenInfo();
    uniParam->SetScreenInfo(screenInfo);

    auto width = mirrorSourceDisplayParams->GetFixedWidth();
    auto height = mirrorSourceDisplayParams->GetFixedHeight();
    Drawing::Rect rect(0, 0, width, height);
    curCanvas->ClipRect(rect, Drawing::ClipOp::INTERSECT, false);
    auto offsetX = mirrorSourceDisplayParams->GetOffsetX();
    auto offsetY = mirrorSourceDisplayParams->GetOffsetY();
    curCanvas->Translate(-offsetX, -offsetY);
    curCanvas->ConcatMatrix(mirrorSourceDisplayParams->GetMatrix());
    RSRenderParams::SetParentSurfaceMatrix(curCanvas->GetTotalMatrix());

    // Render mirror content from the source tree
    mirrorSourceDisplayDrawable->RSRenderNodeDrawable::OnDraw(*curCanvas);
    mirrorSourceDisplayDrawable->DrawAdditionalContent(*curCanvas);

    bool displayP3Enable = screenParams->GetNewColorSpace() == GRAPHIC_COLOR_GAMUT_DISPLAY_P3;
    drawable.DrawCurtainScreen();
    // 1.f: wired screen not use hdr, use default value 1.f
    RSUniRenderUtil::SwitchColorFilter(*curCanvas, 1.f, displayP3Enable);

    uniParam->SetOpDropped(isOpDropped);
    RSUniRenderThread::Instance().SetBlackList({});
    curCanvas->Restore();
    rsDirtyRectsDfx.OnDrawVirtual(*curCanvas);
    if (specialLayerMgr.Find(SpecialLayerType::HAS_PROTECTED)) {
        canvasMatrix.PreTranslate(-offsetX, -offsetY);
        RSDrmUtil::DRMCreateLayer(processor, canvasMatrix);
        screenParams->SetGlobalZOrder(screenParams->GetGlobalZOrder() + 1);
    }
}

void RSMultiScreenUtil::DrawVirtualMirrorDisplay(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    // uniParam/drawable/mirrorSourceDisplayParams/renderParams_ not null in caller
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    auto [multiScreenParams, isValid] = RSMultiScreenUtil::GetMultiScreenParams(params);
    if (!isValid) {
        RS_LOGE("RSMultiScreenUtil::%{public}s params are invalid", __func__);
        return;
    }

    auto& [screenDrawable, screenParams, mirrorSourceDisplayDrawable, mirrorSourceDisplayParams,
        mirrorSourceScreenDrawable, mirrorSourceScreenParams] = multiScreenParams;

    auto virtualProcesser = RSProcessor::ReinterpretCast<RSUniRenderVirtualProcessor>(processor);
    if (!virtualProcesser) {
        RS_LOGE("RSMultiScreenUtil::%{public}s virtualProcesser is null", __func__);
        return;
    }
    virtualProcesser->CanvasInit(drawable);

    auto cacheImage = mirrorSourceScreenDrawable ? mirrorSourceScreenDrawable->GetCacheImgForCapture() : nullptr;
    auto specialLayerType = RSSpecialLayerUtils::GetSpecialLayerStateInVisibleRect(&params, screenParams);
    // if specialLayer is visible and no CacheImg
    bool needProcessSpecialLayer = mirrorSourceDisplayParams->IsSecurityDisplay() != params.IsSecurityDisplay() &&
        specialLayerType == DisplaySpecialLayerState::HAS_SPECIAL_LAYER;
    bool needProcessSecLayer = RSSpecialLayerUtils::NeedProcessSecLayerInDisplay(
        drawable.enableVisibleRect_, *screenParams, params, *mirrorSourceDisplayParams);

    std::bitset<RebuildReason::MAX_VALUE> rebuildReasonFlag;
    rebuildReasonFlag.set(RebuildReason::PROCESS_SPECIAL_LAYER, needProcessSpecialLayer);
    rebuildReasonFlag.set(RebuildReason::DRAW_SEC_MASK, needProcessSecLayer);
    rebuildReasonFlag.set(RebuildReason::MIRROR_SCREEN_HDR_PRESENT, screenParams->GetHDRPresent());
    rebuildReasonFlag.set(RebuildReason::MIRROR_SOURCE_HDR_PRESENT, mirrorSourceScreenParams->GetHDRPresent());
    rebuildReasonFlag.set(RebuildReason::CACHE_IMAGE_NULL, cacheImage == nullptr);
    rebuildReasonFlag.set(RebuildReason::VIRTUAL_SCREEN_MUTE, params.GetVirtualScreenMuteStatus());
    rebuildReasonFlag.set(RebuildReason::SCREEN_OFF, mirrorSourceScreenDrawable->IsRenderSkipIfScreenOff());
    rebuildReasonFlag.set(RebuildReason::COLOR_FILTER_MODE, RSUniRenderThread::Instance().IsColorFilterModeOn());

    RenderStrategy curStrategy = rebuildReasonFlag.any() ?
        RenderStrategy::DRAW_VIRTUAL_MIRROR_REBUILD : RenderStrategy::DRAW_VIRTUAL_MIRROR_FROM_CACHE;
    RSMultiScreenUtil::DumpRenderStrategy(drawable, params.GetScreenId(), curStrategy, rebuildReasonFlag.to_string());
    RS_TRACE_NAME_FMT("%s, mirrorSourceScreenId[%" PRIu64 "], rebuildReasonFlag[%s], specialLayerType[%d]",
        __func__, mirrorSourceScreenParams->GetScreenId(), rebuildReasonFlag.to_string().c_str(), specialLayerType);

    if (rebuildReasonFlag.any()) {
        virtualProcesser->SetDrawVirtualMirrorCopy(false);
        RSMultiScreenUtil::DrawVirtualMirrorRebuild(drawable, params, virtualProcesser, *uniParam);
    } else {
        virtualProcesser->SetDrawVirtualMirrorCopy(true);
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(drawable, params, virtualProcesser, *uniParam);
    }
}

void RSMultiScreenUtil::DrawVirtualMirrorFromCache(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSUniRenderVirtualProcessor>& processor,
    RSRenderThreadParams& uniParam)
{
    RS_TRACE_FUNC();
    auto [multiScreenParams, isValid] = RSMultiScreenUtil::GetMultiScreenParams(params);
    if (!isValid) {
        RS_LOGE("RSMultiScreenUtil::%{public}s params are invalid", __func__);
        return;
    }

    auto& [screenDrawable, screenParams, mirrorSourceDisplayDrawable, mirrorSourceDisplayParams,
        mirrorSourceScreenDrawable, mirrorSourceScreenParams] = multiScreenParams;
    auto cacheImage = mirrorSourceScreenDrawable ? mirrorSourceScreenDrawable->GetCacheImgForCapture() : nullptr;
    bool isOpDropped = uniParam.IsOpDropped();
    uniParam.SetOpDropped(false);
#ifdef RS_PROFILER_ENABLED
    if (processor && processor->GetCanvas()) {
        float width = static_cast<float>(processor->GetCanvas()->GetWidth());
        float height = static_cast<float>(processor->GetCanvas()->GetHeight());
        auto canvas = RSCaptureRecorder::GetInstance().TryInstantCapture(width, height, SkpCaptureType::IMG_CACHED);
        if (canvas) {
            processor->GetCanvas()->AddCanvas(canvas);
        }
    }
#endif
    processor->CalculateTransform(drawable.GetOriginScreenRotation());
    RSDirtyRectsDfx rsDirtyRectsDfx(*screenDrawable);
    bool enableVisibleRect = drawable.enableVisibleRect_;
    std::shared_ptr<RSSLRScaleFunction> slrManager = enableVisibleRect ? nullptr : processor->GetSlrManager();
    drawable.curCanvas_ = processor->GetCanvas().get();

    // OffScreenRender will change the drawable.curCanvas_'s target, so you have to use a reference
    auto& curCanvas = drawable.curCanvas_;
    if (!curCanvas) {
        RS_LOGE("RSMultiScreenUtil::%{public}s canvas is null!", __func__);
        return;
    }
    curCanvas->SetOnMultipleScreen(true); // use for hdr content tmo to fixed sdr nits
    /*
     * If Top and Left in curVisibleRect_ are not zero,that means the regional screen mirror position may be offset,
     * and the dirty area location may be incorrect. Need to disable the dirty area.
     */
    const auto& curVisibleRect = drawable.curVisibleRect_;
    if (!uniParam.IsVirtualDirtyEnabled() ||
        (enableVisibleRect && (curVisibleRect.GetTop() > 0 || curVisibleRect.GetLeft() > 0))) {
        std::vector<RectI> emptyRects = {};
        processor->SetRoiRegionToCodec(emptyRects);
    } else {
        auto dirtyRects = drawable.CalculateVirtualDirty(processor, *screenDrawable, params,
            slrManager ? slrManager->GetScaleMatrix() : processor->GetCanvasMatrix());
        rsDirtyRectsDfx.SetVirtualDirtyRects(dirtyRects, screenParams->GetScreenInfo());
        if (processor->GetDisplaySkipInMirror()) {
            RS_TRACE_NAME_FMT("%s, display node skip", __func__);
            curCanvas->RestoreToCount(0);
            return;
        }
    }
    // Clean up the content of the previous frame
    curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);

    auto mirrorSourceScreenInfo = mirrorSourceScreenParams->GetScreenInfo();
    // When mirror scale (SLR or source sampling) is active, the single-self-drawing optimization
    // would draw without the scale and cause display inconsistency. Fall back to normal path.
    bool hasMirrorScale = (slrManager != nullptr) || mirrorSourceScreenInfo.isSamplingOn;
    // If the self-drawing node is not fullscreen, need to re-adaptation curCanvas_ clear
    if (!hasMirrorScale &&
        RSUniRenderUtil::ProcessSingleSelfDrawingNode(*curCanvas, *mirrorSourceScreenParams, params)) {
        return;
    }
    processor->CanvasClipRegionForUniscaleMode();
    RSUniRenderThread::SetCaptureParam(CaptureParam(false, false, true));

    float mirrorSourceSamplingScale = mirrorSourceScreenInfo.isSamplingOn ? mirrorSourceScreenInfo.samplingScale : 1.0f;

    curCanvas->Save();
    if (slrManager) {
        // slrScaleNum maps the sampled source space to the virtual screen while layer matrices are
        // in logical coordinates; the extra samplingScale factor bridges logical -> sampled first.
        auto scaleNum = slrManager->GetScaleNum() * mirrorSourceSamplingScale;
        curCanvas->Scale(scaleNum, scaleNum);
    } else if (mirrorSourceScreenInfo.isSamplingOn) {
        // Layer matrices are collected in logical (pre-sampling) coordinates during the source
        // traversal, while this canvas is based on the sampled source space (mirrored size is
        // multiplied by samplingScale in UpdateMirrorInfo); scale to bridge logical -> sampled.
        curCanvas->Scale(mirrorSourceSamplingScale, mirrorSourceSamplingScale);
    }
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hwcNodes;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hwcTopNodes;
    RSUniRenderUtil::CollectHardwareEnabledNodesByDisplayNodeId(hwcNodes, hwcTopNodes,
        mirrorSourceDisplayDrawable->GetId());
    RSUniRenderUtil::AdjustZOrderAndDrawSurfaceNode(hwcNodes, *curCanvas, *mirrorSourceScreenParams);
    curCanvas->Restore();
    const auto& mirroredScreenProperty = mirrorSourceScreenParams->GetScreenProperty();
    auto widthRatio = mirroredScreenProperty.GetRogWidthRatio();
    auto heightRatio = mirroredScreenProperty.GetRogHeightRatio();
    if (mirroredScreenProperty.GetSamplingMode() == ScreenSamplingMode::DEVICE_GPU &&
        ROSEN_GNE(widthRatio, 0.f) && ROSEN_GNE(heightRatio, 0.f)) {
        curCanvas->Scale(1.0f / widthRatio, 1.0f / heightRatio);
    }

    if (cacheImage && RSSystemProperties::GetDrawMirrorCacheImageEnabled()) {
        RS_TRACE_NAME_FMT("%s, use cacheImage, hwcNodes[%zu], hwcTopNodes[%zu], slrManager[%d]",
            __func__, hwcNodes.size(), hwcTopNodes.size(), slrManager != nullptr);
        if (!enableVisibleRect) {
            processor->ProcessCacheImage(*cacheImage);
        } else {
            RSUniRenderUtil::ProcessCacheImageRect(*curCanvas, *cacheImage, curVisibleRect,
                Drawing::Rect(0, 0, curVisibleRect.GetWidth(), curVisibleRect.GetHeight()));
        }
    } else {
        RS_TRACE_NAME_FMT("%s, use displaySurface, hwcNodes[%zu], hwcTopNodes[%zu], slrManager[%d]",
            __func__, hwcNodes.size(), hwcTopNodes.size(), slrManager != nullptr);
        processor->ProcessScreenSurfaceForRenderThread(*mirrorSourceScreenDrawable);
    }
    if (mirroredScreenProperty.GetSamplingMode() == ScreenSamplingMode::DEVICE_GPU &&
        ROSEN_GNE(widthRatio, 0.f) && ROSEN_GNE(heightRatio, 0.f)) {
        curCanvas->Scale(widthRatio, heightRatio);
    }

    curCanvas->Save();
    if (slrManager) {
        // slrScaleNum maps the sampled source space to the virtual screen while layer matrices are
        // in logical coordinates; the extra samplingScale factor bridges logical -> sampled first.
        auto scaleNum = slrManager->GetScaleNum() * mirrorSourceSamplingScale;
        curCanvas->Scale(scaleNum, scaleNum);
    } else if (mirrorSourceScreenInfo.isSamplingOn) {
        // Layer matrices are collected in logical (pre-sampling) coordinates during the source
        // traversal, while this canvas is based on the sampled source space (mirrored size is
        // multiplied by samplingScale in UpdateMirrorInfo); scale to bridge logical -> sampled.
        curCanvas->Scale(mirrorSourceSamplingScale, mirrorSourceSamplingScale);
    }
    RSUniRenderUtil::AdjustZOrderAndDrawSurfaceNode(hwcTopNodes, *curCanvas, *mirrorSourceScreenParams);
    curCanvas->Restore();

#ifdef RS_PROFILER_ENABLED
    RSCaptureRecorder::GetInstance().EndInstantCapture(SkpCaptureType::IMG_CACHED);
#endif
    RSUniRenderThread::ResetCaptureParam();
    uniParam.SetOpDropped(isOpDropped);
    // Restore the initial state of the canvas to avoid state accumulation
    curCanvas->RestoreToCount(0);
    rsDirtyRectsDfx.OnDrawVirtual(*curCanvas);
}

void RSMultiScreenUtil::DrawVirtualMirrorRebuild(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSUniRenderVirtualProcessor>& processer,
    RSRenderThreadParams& uniParam)
{
    // uniParam/drawable/mirrorSourceDisplayParams not null in caller
    RS_TRACE_FUNC();

    auto [multiScreenParams, isValid] = RSMultiScreenUtil::GetMultiScreenParams(params);
    if (!isValid) {
        RS_LOGE("RSMultiScreenUtil::%{public}s params are invalid", __func__);
        return;
    }

    auto& [screenDrawable, screenParams, mirrorSourceDisplayDrawable, mirrorSourceDisplayParams,
        mirrorSourceScreenDrawable, mirrorSourceScreenParams] = multiScreenParams;
    drawable.curCanvas_ = processer->GetCanvas().get();

    // OffScreenRender will change the drawable.curCanvas_'s target, so you have to use a reference
    auto& curCanvas = drawable.curCanvas_;
    if (!curCanvas) {
        RS_LOGE("RSMultiScreenUtil::%{public}s canvas is null!", __func__);
        return;
    }
    bool enableVisibleRect = drawable.enableVisibleRect_;
    // for HDR
    if (screenParams->GetHDRPresent()) {
        RS_LOGD("RSMultiScreenUtil::%{public}s HDRCast isHDREnabledVirtualScreen true", __func__);
        curCanvas->SetHDREnabledVirtualScreen(true);
        curCanvas->SetHdrOn(true);
    } else {
        curCanvas->SetOnMultipleScreen(true);
    }
    curCanvas->SetDisableFilterCache(true);
    if (params.GetVirtualScreenMuteStatus() || RSSpecialLayerUtils::NeedProcessSecLayerInDisplay(
        enableVisibleRect, *screenParams, params, *mirrorSourceDisplayParams)) {
#ifdef RS_PROFILER_ENABLED
        float width = static_cast<float>(curCanvas->GetWidth());
        float height = static_cast<float>(curCanvas->GetHeight());
        auto canvas = RSCaptureRecorder::GetInstance().TryInstantCapture(width, height, SkpCaptureType::ON_CAPTURE);
        if (canvas) {
            curCanvas->AddCanvas(canvas);
        }
#endif
        std::vector<RectI> emptyRects = {};
        processer->SetRoiRegionToCodec(emptyRects);
        drawable.DrawSecurityMask();
#ifdef RS_PROFILER_ENABLED
        RSCaptureRecorder::GetInstance().EndInstantCapture(SkpCaptureType::ON_CAPTURE);
#endif
        drawable.virtualDirtyNeedRefresh_ = true;
        curCanvas->RestoreToCount(0);
        return;
    }
    curCanvas->Save();
    processer->ScaleMirrorIfNeed(drawable.GetOriginScreenRotation(), *curCanvas);
    const auto& mirrorSourceScreenProperty = mirrorSourceScreenParams->GetScreenProperty();
    auto fixedWidth = mirrorSourceDisplayParams->GetFixedWidth();
    auto fixedHeight = mirrorSourceDisplayParams->GetFixedHeight();
    drawable.UpdateSlrScale(mirrorSourceScreenProperty, fixedWidth, fixedHeight);
    drawable.ScaleCanvasIfNeeded(mirrorSourceScreenProperty);

    RSDirtyRectsDfx rsDirtyRectsDfx(*screenDrawable);
    if (uniParam.IsVirtualDirtyEnabled() && !enableVisibleRect) {
        Drawing::Matrix matrix = curCanvas->GetTotalMatrix();
        std::vector<RectI> dirtyRects = drawable.CalculateVirtualDirty(processer, *screenDrawable, params, matrix);
        rsDirtyRectsDfx.SetVirtualDirtyRects(dirtyRects, screenParams->GetScreenInfo());
        if (processer->GetDisplaySkipInMirror()) {
            RS_TRACE_NAME_FMT("%s, display node skip", __func__);
            curCanvas->RestoreToCount(0);
            return;
        }
    } else {
        std::vector<RectI> emptyRects = {};
        processer->SetRoiRegionToCodec(emptyRects);
    }
    // Clean up the content of the previous frame
    curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);

    // If the self-drawing node is not fullscreen, need to re-adaptation curCanvas_ clear
    if (RSUniRenderUtil::ProcessSingleSelfDrawingNode(*curCanvas, *mirrorSourceScreenParams, params)) {
        return;
    }
    bool isSamplingOn = mirrorSourceScreenProperty.GetIsSamplingOn();
    processer->CanvasClipRegionForUniscaleMode(drawable.visibleClipRectMatrix_, isSamplingOn);
    // Set whitelist rect to meta data before concat matrix
    RSSpecialLayerUtils::SetWhiteListRectToMetaData(
        *curCanvas, uniParam, screenParams->GetScreenProperty(), *mirrorSourceDisplayParams, drawable.scaleManager_);
    curCanvas->ConcatMatrix(mirrorSourceDisplayParams->GetMatrix());
    drawable.PrepareOffscreenRender(*mirrorSourceDisplayDrawable, false, false,
        screenParams->GetFixVirtualBuffer10Bit());
    // Add this flag to disable color picking operations during mirror screen redrawing
    curCanvas->SetIsDrawingOffscreenMirror(true);
#ifdef RS_PROFILER_ENABLED
    float width = static_cast<float>(curCanvas->GetWidth());
    float height = static_cast<float>(curCanvas->GetHeight());
    auto canvas = RSCaptureRecorder::GetInstance().TryInstantCapture(width, height, SkpCaptureType::ON_CAPTURE);
    if (canvas) {
        curCanvas->AddCanvas(canvas);
    }
#endif
    // set mirror screen capture param
    // Don't need to scale here since the canvas has been switched from mirror frame to offscreen
    // surface in PrepareOffscreenRender() above. The offscreen surface has the same size as
    // the main display that's why no need additional scale.
    RSUniRenderThread::SetCaptureParam(CaptureParam(false, false, true));
    RSUniRenderThread::GetCaptureParam().virtualScreenId_ = params.GetScreenId();
    RSRenderParams::SetParentSurfaceMatrix(curCanvas->GetTotalMatrix());
    bool isOpDropped = uniParam.IsOpDropped();
    uniParam.SetOpDropped(false); // disable partial render

    // Render mirror content from the source tree
    if (mirrorSourceDisplayDrawable->ShouldPaint()) {
        mirrorSourceDisplayDrawable->offsetX_ = mirrorSourceScreenProperty.GetOffsetX();
        mirrorSourceDisplayDrawable->offsetY_ = mirrorSourceScreenProperty.GetOffsetY();

        // The paintFilterCanvas here is offScreen Canvas
        RSAutoCanvasRestore acr(curCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);

        // When set isMirror_ of CaptureParam true, the execution falls through to children's OnCapture function
        mirrorSourceDisplayDrawable->RSRenderNodeDrawable::OnCapture(*curCanvas);
        mirrorSourceDisplayDrawable->DrawAdditionalContent(*curCanvas);
    } else {
        RS_TRACE_NAME_FMT("%s, mirrorSourceDisplayDrawable shouldn't paint", __func__);
        RS_LOGI("RSMultiScreenUtil::%{public}s mirrorSourceDisplayDrawable shouldn't paint!", __func__);
    }

    uniParam.SetOpDropped(isOpDropped);
    RSUniRenderThread::ResetCaptureParam();
#ifdef RS_PROFILER_ENABLED
    RSCaptureRecorder::GetInstance().EndInstantCapture(SkpCaptureType::ON_CAPTURE);
#endif
    Drawing::SamplingOptions samplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    drawable.FinishOffscreenRender(samplingOptions, isSamplingOn);
    // Restore the initial state of the canvas to avoid state accumulation
    curCanvas->RestoreToCount(0);
    rsDirtyRectsDfx.OnDrawVirtual(*curCanvas);
}

void RSMultiScreenUtil::DrawVirtualExtend(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    const std::shared_ptr<RSUniRenderVirtualProcessor>& processor)
{
    auto [_, screenParam] = drawable.GetScreenParams(params);
    if (!screenParam) {
        RS_LOGE("RSMultiScreenUtil::%{public}s screenParam is nullptr", __func__);
        return;
    }

    if (!processor) {
        RS_LOGE("RSMultiScreenUtil::%{public}s processor is nullptr", __func__);
        return;
    }

    RS_TRACE_NAME_FMT("%s, hdr[%d], isMultiSurface[%d]", __func__, screenParam->GetHDRPresent(),
        processor->IsMultiSurfaceExtendMode());
    RSMultiScreenUtil::DumpRenderStrategy(drawable, params.GetScreenId(), RenderStrategy::DRAW_VIRTUAL_EXTEND, "");

    const RSScreenProperty& screenProperty = screenParam->GetScreenProperty();
    // OffScreenRender will change the drawable.curCanvas_'s target, so you have to use a reference
    auto& canvas = drawable.curCanvas_;
    RSAutoCanvasRestore acr(canvas);
    params.ApplyAlphaAndMatrixToCanvas(*canvas);

    // Check for multi-surface extend mode (only when surfaces have specified regions)
    if (processor->IsMultiSurfaceExtendMode()) {
        if (screenParam->GetHDRPresent()) {
            canvas->SetHDREnabledVirtualScreen(true);
            canvas->SetHdrOn(true);
        }
        // Multi-surface with regions: render to offscreen, then blit regions to each surface
        drawable.PrepareOffscreenRender(drawable, false, false, screenParam->GetFixVirtualBuffer10Bit());
        drawable.RSRenderNodeDrawable::OnDraw(*canvas);

        // Get offscreen image and blit to each surface
        auto offscreenImage = drawable.offscreenSurface_ ? drawable.offscreenSurface_->GetImageSnapshot() : nullptr;
        if (offscreenImage) {
            processor->BlitRegionsToSurfaces(offscreenImage);
        } else {
            RS_LOGE("RSMultiScreenUtil::%{public}s Failed to get offscreen image for multi-surface extend mode",
                __func__);
        }
        // Note: FinishOffscreenRender is not needed here since we're not drawing back to a single canvas
        drawable.canvasBackup_ = nullptr;
    } else if (screenParam->GetHDRPresent()) {
        RS_LOGD("RSMultiScreenUtil::%{public}s HDRCast isHDREnabledVirtualScreen true", __func__);
        canvas->SetHDREnabledVirtualScreen(true);
        canvas->SetHdrOn(true);
        drawable.PrepareOffscreenRender(drawable, false, false, screenParam->GetFixVirtualBuffer10Bit());
        drawable.RSRenderNodeDrawable::OnDraw(*canvas);
        Drawing::SamplingOptions samplingOptions(Drawing::FilterMode::NEAREST, Drawing::MipmapMode::NONE);
        drawable.FinishOffscreenRender(samplingOptions, screenProperty.GetIsSamplingOn());
    } else {
        canvas->SetOnMultipleScreen(true); // use for hdr content tmo to fixed sdr nits
        drawable.RSRenderNodeDrawable::OnDraw(*canvas);
    }
}

void RSMultiScreenUtil::DumpRenderStrategy(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    ScreenId screenId,
    RenderStrategy path,
    const std::string& reason)
{
    if (drawable.lastFrameRenderStrategy_ == path) {
        return;
    }

    RS_TRACE_NAME_FMT("%s ScreenId[%" PRIu64 "] with nodeId[%" PRIu64
        "] render changed from [%d] to [%d] because of [%s]", __func__, screenId,
        drawable.GetId(), static_cast<int>(drawable.lastFrameRenderStrategy_), static_cast<int>(path), reason.c_str());

    RS_LOGI("RSMultiScreenUtil::%{public}s ScreenId[%{public}" PRIu64 "] with nodeId[%{public}" PRIu64
        "] render changed from [%{public}d] to [%{public}d] because of [%{public}s]", __func__, screenId,
        drawable.GetId(), static_cast<int>(drawable.lastFrameRenderStrategy_), static_cast<int>(path), reason.c_str());

    drawable.lastFrameRenderStrategy_ = path;
}

std::pair<MultiScreenParams, bool> RSMultiScreenUtil::GetMultiScreenParams(RSLogicalDisplayRenderParams& params)
{
    MultiScreenParams multiScreenParams;

    auto screenDrawable = std::static_pointer_cast<RSScreenRenderNodeDrawable>(
        params.GetAncestorScreenDrawable().lock());
    if (!screenDrawable || screenDrawable->GetNodeType() != RSRenderNodeType::SCREEN_NODE) {
        RS_LOGE("RSMultiScreenUtil::%{public}s, screenDrawable is nullptr", __func__);
        return { multiScreenParams, false };
    }
    multiScreenParams.screenDrawable = screenDrawable;

    auto screenParams = static_cast<RSScreenRenderParams*>(screenDrawable->GetRenderParams().get());
    if (!screenParams) {
        RS_LOGE("RSMultiScreenUtil::%{public}s, screenParams is nullptr", __func__);
        return { multiScreenParams, false };
    }
    multiScreenParams.screenParams = screenParams;

    auto mirrorSourceDisplayDrawable = std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(
        params.GetMirrorSourceDrawable().lock());
    if (!mirrorSourceDisplayDrawable) {
        RS_LOGE("RSMultiScreenUtil::%{public}s, mirrorSourceDisplayDrawable is nullptr", __func__);
        return { multiScreenParams, false };
    }
    multiScreenParams.mirrorSourceDisplayDrawable = mirrorSourceDisplayDrawable;

    auto mirrorSourceDisplayParams =
        static_cast<RSLogicalDisplayRenderParams*>(mirrorSourceDisplayDrawable->GetRenderParams().get());
    if (!mirrorSourceDisplayParams) {
        RS_LOGE("RSMultiScreenUtil::%{public}s, mirrorSourceDisplayParams is nullptr", __func__);
        return { multiScreenParams, false };
    }
    multiScreenParams.mirrorSourceDisplayParams = mirrorSourceDisplayParams;

    auto mirrorSourceScreenDrawable = std::static_pointer_cast<RSScreenRenderNodeDrawable>(
        mirrorSourceDisplayParams->GetAncestorScreenDrawable().lock());
    if (!mirrorSourceScreenDrawable) {
        RS_LOGE("RSMultiScreenUtil::%{public}s, mirrorSourceScreenDrawable is nullptr", __func__);
        return { multiScreenParams, false };
    }
    multiScreenParams.mirrorSourceScreenDrawable = mirrorSourceScreenDrawable;

    auto mirrorSourceScreenParams =
        static_cast<RSScreenRenderParams*>(mirrorSourceScreenDrawable->GetRenderParams().get());
    if (!mirrorSourceScreenParams) {
        RS_LOGE("RSMultiScreenUtil::%{public}s, mirrorSourceScreenParams is nullptr", __func__);
        return { multiScreenParams, false };
    }
    multiScreenParams.mirrorSourceScreenParams = mirrorSourceScreenParams;

    return { multiScreenParams, true };
}

namespace {
// Runs on the RSUniRenderThread and consumes only the main-thread snapshot of drawables (see
// RSLogicalDisplayRenderNode::ResolveWindowRecordSnapshot). Drawables and their params are the
// render-thread side representation, so this never touches RSRenderNodeMap or RSRenderNode.
// The snapshot already contains main-window-type surfaces only, hence no node type check here.
Drawing::RectI ComputeRecordBBox(const std::vector<RSRenderNodeDrawableAdapter::WeakPtr>& recordDrawables)
{
    int32_t left = INT32_MAX;
    int32_t top = INT32_MAX;
    int32_t right = INT32_MIN;
    int32_t bottom = INT32_MIN;
    bool hasValidRect = false;
    for (const auto& weakDrawable : recordDrawables) {
        auto drawable = weakDrawable.lock();
        if (!drawable || !drawable->GetRenderParams()) {
            continue;
        }
        // AbsDrawRect is left/top/width/height; reject a non-positive size (or inverted) first because
        // GetRight()/GetBottom() add in int32, which is signed-overflow UB for an extreme origin.
        const auto& absRect = drawable->GetRenderParams()->GetAbsDrawRect();
        if (absRect.IsEmpty()) {
            continue;
        }
        // Widen the sum to int64 and keep the rect only when right/bottom fit in int32, so no later
        // Drawing::RectI consumer sees an overflowed edge; a positive size can only overflow upward.
        const int64_t rectRight = static_cast<int64_t>(absRect.GetLeft()) + static_cast<int64_t>(absRect.GetWidth());
        const int64_t rectBottom = static_cast<int64_t>(absRect.GetTop()) + static_cast<int64_t>(absRect.GetHeight());
        if (rectRight > INT32_MAX || rectBottom > INT32_MAX) {
            continue;
        }
        // Rebuild as left/top/right/bottom and drop invalid rects before the min/max merge, or one
        // degenerate window would stretch the bbox to cover unrelated geometry.
        Drawing::RectI rect(absRect.GetLeft(), absRect.GetTop(), static_cast<int32_t>(rectRight),
            static_cast<int32_t>(rectBottom));
        if (!rect.IsValid()) {
            continue;
        }
        hasValidRect = true;
        left = std::min(left, rect.GetLeft());
        top = std::min(top, rect.GetTop());
        right = std::max(right, rect.GetRight());
        bottom = std::max(bottom, rect.GetBottom());
    }
    if (!hasValidRect) {
        // No contributor had geometry: report empty so the screen gate retains the previous frame.
        return {};
    }
    return {left, top, right, bottom};
}

void ApplyGravityTransform(RSPaintFilterCanvas* curCanvas, const Drawing::RectI& bbox,
    int32_t canvasW, int32_t canvasH, WindowRecordFit fit, ScreenRotation rotation)
{
    // IsValid() computes the span with int64 and rejects rects whose span exceeds int32, so the
    // int32 subtractions below cannot overflow; the canvas sizes are guarded the same way as in
    // ComputeGravityRect.
    if (!bbox.IsValid() || canvasW <= 0 || canvasH <= 0) {
        return;
    }
    int32_t contentW = bbox.GetWidth();
    int32_t contentH = bbox.GetHeight();
    auto targetRect = RSMultiScreenUtil::ComputeGravityRect(canvasW, canvasH, contentW, contentH, fit, rotation);
    curCanvas->ClipRect(targetRect, Drawing::ClipOp::INTERSECT, false);
    float sx = static_cast<float>(targetRect.GetWidth()) / contentW;
    float sy = static_cast<float>(targetRect.GetHeight()) / contentH;
    float tx = static_cast<float>(targetRect.GetLeft()) - static_cast<float>(bbox.GetLeft()) * sx;
    float ty = static_cast<float>(targetRect.GetTop()) - static_cast<float>(bbox.GetTop()) * sy;
    curCanvas->Translate(tx, ty);
    curCanvas->Scale(sx, sy);
}
} // namespace

Drawing::RectI RSMultiScreenUtil::ComputeGravityRect(int32_t canvasW, int32_t canvasH,
    int32_t contentW, int32_t contentH, WindowRecordFit fit, ScreenRotation rotation)
{
    // A non-positive content/canvas size would make scale inf and static_cast<int32_t>(NaN)
    // undefined behavior. Return an empty rect so callers skip the clip/scale path via
    // RectI::IsValid().
    if (contentW <= 0 || contentH <= 0 || canvasW <= 0 || canvasH <= 0) {
        RS_LOGE("RSMultiScreenUtil::%{public}s invalid size canvas[%{public}d,%{public}d] "
            "content[%{public}d,%{public}d]", __func__, canvasW, canvasH, contentW, contentH);
        return {0, 0, 0, 0};
    }
    float scale = std::min(static_cast<float>(canvasW) / contentW,
                           static_cast<float>(canvasH) / contentH);
    int32_t scaledW = static_cast<int32_t>(contentW * scale);
    int32_t scaledH = static_cast<int32_t>(contentH * scale);
    int32_t x = 0;
    int32_t y = 0;
    if (fit == WindowRecordFit::ASPECT_FIT) {
        x = (canvasW - scaledW) / 2;
        y = (canvasH - scaledH) / 2;
    } else {
        // ASPECT_FIT_TOP_LEFT: align content to buffer top-left corner.
        // Canvas is rotated relative to buffer, so (0,0) in canvas space maps to
        // different buffer corners depending on rotation.
        if (rotation == ScreenRotation::ROTATION_90) {
            x = 0;
            y = canvasH - scaledH;
        } else if (rotation == ScreenRotation::ROTATION_180) {
            x = canvasW - scaledW;
            y = canvasH - scaledH;
        } else if (rotation == ScreenRotation::ROTATION_270) {
            x = canvasW - scaledW;
            y = 0;
        }
    }
    return {x, y, x + scaledW, y + scaledH};
}

namespace {
constexpr float ROTATION_0_DEG = 0.0f;
constexpr float ROTATION_180_DEG = 180.0f;
constexpr float ROTATION_270_DEG = 270.0f;
constexpr float ROTATION_90_DEG = 90.0f;

float ScreenRotationToDegrees(ScreenRotation rotation)
{
    switch (rotation) {
        case ScreenRotation::ROTATION_90:
            return ROTATION_90_DEG;
        case ScreenRotation::ROTATION_180:
            return ROTATION_180_DEG;
        case ScreenRotation::ROTATION_270:
            return ROTATION_270_DEG;
        default:
            return ROTATION_0_DEG;
    }
}

// Cancels the frames the processor acquired unless the pass reaches PostProcess; RSRenderFrame
// auto-flushes on destruction, so an aborted pass would otherwise publish a blank or partial image.
class WindowRecordFrameCancelGuard {
public:
    explicit WindowRecordFrameCancelGuard(RSUniRenderVirtualProcessor& processor) : processor_(processor) {}
    ~WindowRecordFrameCancelGuard()
    {
        if (!disarmed_) {
            processor_.CancelCurrentFrame();
        }
    }
    WindowRecordFrameCancelGuard(const WindowRecordFrameCancelGuard&) = delete;
    WindowRecordFrameCancelGuard& operator=(const WindowRecordFrameCancelGuard&) = delete;
    void Disarm()
    {
        disarmed_ = true;
    }

private:
    RSUniRenderVirtualProcessor& processor_;
    bool disarmed_ = false;
};

// Entry names passed by the two entry points below so trace and log text stays unchanged.
constexpr char WINDOW_RECORD_SCREEN_FUNC[] = "HandleWindowRecordScreen";
constexpr char WINDOW_RECORD_DISPLAY_FUNC[] = "HandleWindowRecord";

enum class WindowRecordDisplayOutcome {
    NOT_RECORD_ACTIVE,
    SKIP_FRAME,
    RECORD_ACTIVE,
};

// Source-side gates; returns false after arming SKIP_FRAME. Reads only the main-thread snapshot, so
// no RSRenderNode/RSRenderNodeMap state is touched on the render thread.
bool PassRecordSourceGates(RSScreenRenderNodeDrawable& outputDrawable,
    RSLogicalDisplayRenderParams& displayParams)
{
    // Resolved on the RS main thread; an empty snapshot means no drawable main window this frame.
    auto sourceDisplayDrawable = displayParams.GetRecordSourceDisplayDrawable().lock();
    if (sourceDisplayDrawable == nullptr) {
        RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s no drawable main, skip without buffer request",
            WINDOW_RECORD_SCREEN_FUNC);
        outputDrawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return false;
    }
    const auto& sourceParams = sourceDisplayDrawable->GetRenderParams();
    if (sourceParams == nullptr || !sourceParams->GetShouldPaint()) {
        RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s source not paintable, skip without buffer request",
            WINDOW_RECORD_SCREEN_FUNC);
        outputDrawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return false;
    }
    // An empty whitelist means "draw everything" (IsWhiteListNode true for empty), which would
    // record the whole source display instead of the configured windows.
    if (displayParams.GetRecordWhiteListIds().empty()) {
        RS_LOGD("RSMultiScreenUtil::%{public}s no recordable id, skip without buffer request",
            WINDOW_RECORD_SCREEN_FUNC);
        outputDrawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return false;
    }
    if (!displayParams.HasPaintableRecordSurface()) {
        RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s no paintable record surface, skip without buffer request",
            WINDOW_RECORD_SCREEN_FUNC);
        outputDrawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return false;
    }
    return true;
}

// Per-display gate: NOT_RECORD_ACTIVE outside a session, SKIP_FRAME once DrawSkipType::SKIP_FRAME
// is armed, and RECORD_ACTIVE after refreshing the bbox (muted outputs keep it cleared).
WindowRecordDisplayOutcome PrepareRecordDisplayBBox(RSScreenRenderNodeDrawable& outputDrawable,
    const RSRenderNodeDrawableAdapter::SharedPtr& displayDrawable)
{
    // Type gate before the downcast: on a mismatched element static_cast yields a non-null pointer
    // at a wrong offset, which a null check cannot catch.
    if (!displayDrawable || displayDrawable->GetNodeType() != RSRenderNodeType::LOGICAL_DISPLAY_NODE) {
        return WindowRecordDisplayOutcome::NOT_RECORD_ACTIVE;
    }
    auto displayParams = static_cast<RSLogicalDisplayRenderParams*>(displayDrawable->GetRenderParams().get());
    if (displayParams == nullptr || !displayParams->IsRecordSessionActive()) {
        return WindowRecordDisplayOutcome::NOT_RECORD_ACTIVE;
    }
    auto recordDisplay = std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(displayDrawable);
    recordDisplay->SetWindowRecordBBox(Drawing::RectI());
    // A non-paintable output has no content; reject it before the processor acquires an output
    // buffer so the consumer surface is not cleared.
    if (!displayParams->GetShouldPaint()) {
        RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s output not paintable, skip without buffer request",
            WINDOW_RECORD_SCREEN_FUNC);
        outputDrawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return WindowRecordDisplayOutcome::SKIP_FRAME;
    }
    // A muted output paints only the security mask, which needs no source, whitelist, surface or
    // geometry; bypass those gates so the mask is presented.
    if (displayParams->GetVirtualScreenMuteStatus()) {
        return WindowRecordDisplayOutcome::RECORD_ACTIVE;
    }
    if (!PassRecordSourceGates(outputDrawable, *displayParams)) {
        return WindowRecordDisplayOutcome::SKIP_FRAME;
    }
    // No visible main-window geometry leaves no rect for the producer metadata; retain the previous
    // frame instead of producing one the consumer cannot place.
    auto recordBBox = ComputeRecordBBox(displayParams->GetRecordSurfaceDrawables());
    if (!recordBBox.IsValid()) {
        RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s no valid record bbox, skip without buffer request",
            WINDOW_RECORD_SCREEN_FUNC);
        outputDrawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return WindowRecordDisplayOutcome::SKIP_FRAME;
    }
    recordDisplay->SetWindowRecordBBox(recordBBox);
    return WindowRecordDisplayOutcome::RECORD_ACTIVE;
}

// Draws one window-record frame; the cancel guard spans the acquired-frame lifetime and is disarmed
// only after PostProcess publishes it.
void RenderWindowRecordFrame(RSScreenRenderNodeDrawable& drawable, RSUniRenderVirtualProcessor& recordProcessor)
{
    // RSRenderFrame auto-flushes in its destructor; any exit below that skips PostProcess must cancel
    // the acquired frames.
    WindowRecordFrameCancelGuard frameCancelGuard(recordProcessor);
    auto renderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    if (!recordProcessor.InitForRenderThread(drawable, renderEngine, 0)) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_ENGINE_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s processor init failed", WINDOW_RECORD_SCREEN_FUNC);
        return;
    }
    drawable.syncDirtyManager_->ResetDirtyAsSurfaceSize();
    drawable.syncDirtyManager_->UpdateDirty(false);
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (!uniParam) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_PARAMS_OR_UNI_PARAMS_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s uniParam is null", WINDOW_RECORD_SCREEN_FUNC);
        return;
    }

    DirtyStatusAutoUpdate dirtyStatusAutoUpdate(*uniParam, false);
    RSUniRenderThread::BufferManagerGuard bufferGuard;
    drawable.curCanvas_ = recordProcessor.GetCanvas();
    auto& curCanvas = drawable.curCanvas_;
    if (!curCanvas) {
        RS_LOGE("RSMultiScreenUtil::%{public}s canvas is null", WINDOW_RECORD_SCREEN_FUNC);
        return;
    }
    curCanvas->Save();
    curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);
    drawable.RSRenderNodeDrawable::OnDraw(*curCanvas);
    curCanvas->RestoreToCount(0);
    recordProcessor.PostProcess();
    // Published; cancelling now would not retract the frame.
    frameCancelGuard.Disarm();
    bufferGuard.SetAcquireFence(recordProcessor.GetFrameAcquireFence());
    drawable.SetDrawSkipType(DrawSkipType::MIRROR_DRAWABLE_SKIP);
}

// Source display snapshot plus the geometry handed to the display pass.
struct WindowRecordSourceSnapshot {
    std::shared_ptr<RSRenderNodeDrawable> renderDrawable;
    RSLogicalDisplayRenderParams* params = nullptr;
    Drawing::RectI bbox;
};

// Display-level source gates; reads only the main-thread drawable snapshot, staying off
// RSRenderNode/RSRenderNodeMap on the render thread.
bool ResolveWindowRecordSource(RSLogicalDisplayRenderNodeDrawable& drawable, RSLogicalDisplayRenderParams& params,
    WindowRecordSourceSnapshot& source)
{
    auto sourceDisplayDrawable = params.GetRecordSourceDisplayDrawable().lock();
    if (!sourceDisplayDrawable || sourceDisplayDrawable->GetNodeType() != RSRenderNodeType::LOGICAL_DISPLAY_NODE) {
        RS_LOGE("RSMultiScreenUtil::%{public}s source display drawable invalid", WINDOW_RECORD_DISPLAY_FUNC);
        return false;
    }
    auto sourceDrawable = std::static_pointer_cast<RSRenderNodeDrawable>(sourceDisplayDrawable);
    if (!sourceDrawable->ShouldPaint() || !sourceDrawable->GetRenderParams()) {
        RS_LOGE("RSMultiScreenUtil::%{public}s source drawable invalid", WINDOW_RECORD_DISPLAY_FUNC);
        return false;
    }
    auto bbox = drawable.GetWindowRecordBBox();
    if (!bbox.IsValid()) {
        // Direct callers that did not pass through the screen gate must still validate geometry.
        bbox = ComputeRecordBBox(params.GetRecordSurfaceDrawables());
    }
    if (!bbox.IsValid()) {
        RS_LOGE("RSMultiScreenUtil::%{public}s no valid record bbox", WINDOW_RECORD_DISPLAY_FUNC);
        return false;
    }
    // The type gate above guarantees these are logical display params.
    source.renderDrawable = sourceDrawable;
    source.params = static_cast<RSLogicalDisplayRenderParams*>(sourceDrawable->GetRenderParams().get());
    source.bbox = bbox;
    return true;
}

// Resolves the rotation to apply this frame and refreshes the producer-side source state.
ScreenRotation ResolveWindowRecordRotation(RSLogicalDisplayRenderNodeDrawable& drawable,
    const WindowRecordSourceSnapshot& source, RSScreenRenderParams* screenParams,
    RSUniRenderVirtualProcessor& processor)
{
    bool canvasRotation = false;
    if (screenParams) {
        canvasRotation = screenParams->GetScreenProperty().GetCanvasRotation();
    }
    ScreenRotation screenCorrection = ScreenRotation::ROTATION_0;
    auto sourceScreenDrawable = source.params->GetAncestorScreenDrawable().lock();
    if (sourceScreenDrawable && sourceScreenDrawable->GetNodeType() == RSRenderNodeType::SCREEN_NODE) {
        auto sourceScreenParams = static_cast<RSScreenRenderParams*>(sourceScreenDrawable->GetRenderParams().get());
        if (sourceScreenParams) {
            screenCorrection = sourceScreenParams->GetScreenProperty().GetScreenCorrection();
        }
        processor.SetWindowRecordSourceScreen(sourceScreenDrawable->GetId());
    }
    auto sourceRotation = source.params->GetScreenRotation();
    // Follow source rotation changes as well as first-frame and canvas-rotation updates.
    if (drawable.IsFirstTimeToProcessor() || canvasRotation ||
        sourceRotation != drawable.GetOriginScreenRotation()) {
        drawable.SetOriginScreenRotation(sourceRotation);
    }
    // rotationAngle = originScreenRotation - screenCorrection, applied on every frame.
    auto rotationDiff = static_cast<int>(drawable.GetOriginScreenRotation()) - static_cast<int>(screenCorrection);
    return static_cast<ScreenRotation>((rotationDiff + SCREEN_ROTATION_NUM) % SCREEN_ROTATION_NUM);
}

// Rotates the canvas and swaps the logical extents to match the transform applied.
void RotateWindowRecordCanvas(RSPaintFilterCanvas& canvas, ScreenRotation rotation,
    int32_t& canvasW, int32_t& canvasH)
{
    if (rotation == ScreenRotation::ROTATION_90) {
        canvas.Translate(canvasW / 2.0f, canvasH / 2.0f);
        canvas.Rotate(90, 0, 0);
        canvas.Translate(-canvasH / 2.0f, -canvasW / 2.0f);
        std::swap(canvasW, canvasH);
    } else if (rotation == ScreenRotation::ROTATION_180) {
        canvas.Rotate(180, canvasW / 2.0f, canvasH / 2.0f);
    } else if (rotation == ScreenRotation::ROTATION_270) {
        canvas.Translate(canvasW / 2.0f, canvasH / 2.0f);
        canvas.Rotate(270, 0, 0);
        canvas.Translate(-canvasH / 2.0f, -canvasW / 2.0f);
        std::swap(canvasW, canvasH);
    }
}

// Maps the bbox through the pre-gravity matrix and reports both rects to the producer surface;
// missing metadata is only logged since the frame content stays valid.
void UpdateWindowRecordFrameRect(RSUniRenderVirtualProcessor& processor, const Drawing::RectI& bbox,
    const Drawing::Matrix& rotMatrix, int32_t canvasW, int32_t canvasH, WindowRecordFit fit,
    ScreenRotation rotation)
{
    if (!bbox.IsValid()) {
        return;
    }
    int32_t contentW = bbox.GetWidth();
    int32_t contentH = bbox.GetHeight();
    auto targetRect = RSMultiScreenUtil::ComputeGravityRect(canvasW, canvasH, contentW, contentH, fit, rotation);
    Drawing::Rect targetRectF(static_cast<float>(targetRect.GetLeft()),
        static_cast<float>(targetRect.GetTop()),
        static_cast<float>(targetRect.GetRight()),
        static_cast<float>(targetRect.GetBottom()));
    Drawing::Rect bufferRectF;
    rotMatrix.MapRect(bufferRectF, targetRectF);
    auto curFrameRect = Drawing::RectI(static_cast<int32_t>(bufferRectF.GetLeft()),
        static_cast<int32_t>(bufferRectF.GetTop()),
        static_cast<int32_t>(bufferRectF.GetRight()),
        static_cast<int32_t>(bufferRectF.GetBottom()));
    if (curFrameRect.IsValid()) {
        float angle = ScreenRotationToDegrees(rotation);
        Rect surfaceCurRect = { curFrameRect.GetLeft(), curFrameRect.GetTop(),
            curFrameRect.GetWidth(), curFrameRect.GetHeight() };
        Rect surfaceOrigRect = { bbox.GetLeft(), bbox.GetTop(), bbox.GetWidth(), bbox.GetHeight() };
        GSError ret = processor.SetScreenInfoForWindowRecord(surfaceCurRect, surfaceOrigRect, angle);
        if (ret != GSERROR_OK) {
            // The frame content is still valid; only the accompanying metadata is missing.
            RS_LOGE("RSMultiScreenUtil::%{public}s SetScreenInfoForWindowRecord failed ret=%{public}d",
                WINDOW_RECORD_DISPLAY_FUNC, static_cast<int>(ret));
        }
    }
    RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s originalRect[%d,%d,%d,%d] currentFrameRect[%d,%d,%d,%d]",
        WINDOW_RECORD_DISPLAY_FUNC, bbox.GetLeft(), bbox.GetTop(), bbox.GetRight(), bbox.GetBottom(),
        curFrameRect.GetLeft(), curFrameRect.GetTop(), curFrameRect.GetRight(), curFrameRect.GetBottom());
}

// Captures recorded surfaces with the record-only filter state; NodeListGuard restores the shared
// filter lists/record flag and the render flags are restored below, on every exit path.
void CaptureWindowRecordSurfaces(RSPaintFilterCanvas& canvas, RSLogicalDisplayRenderNodeDrawable& drawable,
    RSScreenRenderParams* screenParams, RSLogicalDisplayRenderParams& params,
    RSRenderNodeDrawable& sourceDrawable, const RSWindowRecordConfig& config)
{
    RSUniRenderThread::NodeListGuard nodeListGuard;
    // Mixed leash persistent ids and surface node ids are resolved on the main thread; the
    // record-only capture flag also matches a leashless window by its own surface node id.
    RSUniRenderThread::Instance().SetWhiteList(params.GetRecordWhiteListIds());
    if (screenParams) {
        const auto& screenProperty = screenParams->GetScreenProperty();
        drawable.currentBlackList_ = RSSpecialLayerUtils::GetMergeBlackListInRenderThread(screenProperty);
        RSUniRenderThread::Instance().SetBlackList(drawable.currentBlackList_);
        RSUniRenderThread::Instance().SetTypeBlackList(screenProperty.GetTypeBlackList());
    }
    const bool secExemption = params.GetSecurityExemption();
    RSUniRenderThread::SetCaptureParam(CaptureParam(false, false, true));
    RSUniRenderThread::GetCaptureParam().virtualScreenId_ = params.GetScreenId();
    RSUniRenderThread::GetCaptureParam().isWindowRecord_ = true;
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    // Save and restore the shared render-thread state overridden below (OpDropped / SecurityDisplay
    // / SecExemption / parentSurfaceMatrix).
    bool isOpDropped = false;
    bool prevSecurityDisplay = false;
    bool prevSecExemption = false;
    if (uniParam) {
        isOpDropped = uniParam->IsOpDropped();
        prevSecurityDisplay = uniParam->IsSecurityDisplay();
        prevSecExemption = uniParam->GetSecExemption();
        uniParam->SetOpDropped(false);
        uniParam->SetSecurityDisplay(true);
        uniParam->SetSecExemption(secExemption);
    }
    const Drawing::Matrix parentSurfaceMatrix = RSRenderParams::GetParentSurfaceMatrix();
    RSRenderParams::SetParentSurfaceMatrix(canvas.GetTotalMatrix());
    sourceDrawable.RSRenderNodeDrawable::OnCapture(canvas);
    RSRenderParams::SetParentSurfaceMatrix(parentSurfaceMatrix);
    if (uniParam) {
        uniParam->SetOpDropped(isOpDropped);
        uniParam->SetSecurityDisplay(prevSecurityDisplay);
        uniParam->SetSecExemption(prevSecExemption);
    }
    canvas.Restore();
    RSUniRenderThread::ResetCaptureParam();
    RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s surfaces[%zu] fit[%d]", WINDOW_RECORD_DISPLAY_FUNC,
        config.surfaceNodeIds.size(), static_cast<int>(config.renderFit));
}
} // namespace

void RSMultiScreenUtil::HandleWindowRecordScreen(
    RSScreenRenderNodeDrawable& drawable,
    RSScreenRenderParams& params,
    const std::shared_ptr<RSProcessor>& processor)
{
    // No resolvable main window on this screen: skip before the processor requests an output
    // buffer instead of publishing a blank frame.
    bool hasRecordActiveDisplay = false;
    for (const auto& displayDrawable : params.GetDisplayDrawables()) {
        auto outcome = PrepareRecordDisplayBBox(drawable, displayDrawable);
        if (outcome == WindowRecordDisplayOutcome::NOT_RECORD_ACTIVE) {
            continue;
        }
        hasRecordActiveDisplay = true;
        if (outcome == WindowRecordDisplayOutcome::SKIP_FRAME) {
            return;
        }
    }
    if (!hasRecordActiveDisplay) {
        RS_TRACE_NAME_FMT("RSMultiScreenUtil::%s no record-active display, skip without buffer request", __func__);
        drawable.SetDrawSkipType(DrawSkipType::SKIP_FRAME);
        return;
    }
    if (!processor) {
        drawable.SetDrawSkipType(DrawSkipType::RENDER_ENGINE_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s processor init failed", __func__);
        return;
    }
    // Validate the processor type before it acquires frames: only the virtual processor starts this
    // path's frame lifecycle and can cancel what it acquired.
    auto recordProcessor = RSProcessor::ReinterpretCast<RSUniRenderVirtualProcessor>(processor);
    if (!recordProcessor) {
        drawable.SetDrawSkipType(DrawSkipType::EXPAND_PROCESSOR_NULL);
        RS_LOGE("RSMultiScreenUtil::%{public}s expandProcessor is null", __func__);
        return;
    }
    RenderWindowRecordFrame(drawable, *recordProcessor);
}

void RSMultiScreenUtil::HandleWindowRecord(
    RSLogicalDisplayRenderNodeDrawable& drawable,
    RSLogicalDisplayRenderParams& params,
    RSUniRenderVirtualProcessor& processor)
{
    auto curCanvas = drawable.curCanvas_;
    if (!curCanvas) {
        RS_LOGE("RSMultiScreenUtil::%{public}s canvas is null", __func__);
        return;
    }
    // Mute precedes the whitelist/source early returns so a muted output still shows the security
    // mask when the snapshot resolves to nothing.
    if (params.GetVirtualScreenMuteStatus()) {
        drawable.DrawSecurityMask();
        drawable.virtualDirtyNeedRefresh_ = true;
        return;
    }
    const auto& config = params.GetWindowRecordConfig();
    // An empty whitelist disables filtering; return before Save so the Save/Restore pair stays balanced.
    if (params.GetRecordWhiteListIds().empty()) {
        RS_LOGD("RSMultiScreenUtil::%{public}s empty record whitelist, skip frame", __func__);
        return;
    }
    WindowRecordSourceSnapshot source;
    if (!ResolveWindowRecordSource(drawable, params, source)) {
        return;
    }
    curCanvas->Save();

    auto [screenDrawable, screenParams] = drawable.GetScreenParams(params);
    auto rotation = ResolveWindowRecordRotation(drawable, source, screenParams, processor);
    int32_t canvasW = curCanvas->GetWidth();
    int32_t canvasH = curCanvas->GetHeight();
    RotateWindowRecordCanvas(*curCanvas, rotation, canvasW, canvasH);
    // Capture M_rot: canvas->buffer matrix after rotation, before gravity transform; maps
    // targetRect (canvas scope) to buffer coords for currentFrameRect.
    auto rotMatrix = curCanvas->GetTotalMatrix();
    ApplyGravityTransform(curCanvas, source.bbox, canvasW, canvasH, config.renderFit, rotation);

    // Set the record rects on the producer surface: originalRect is the recorded-window bbox in
    // display coords, currentFrameRect where content lands in buffer coords.
    UpdateWindowRecordFrameRect(processor, source.bbox, rotMatrix, canvasW, canvasH, config.renderFit, rotation);
    curCanvas->ConcatMatrix(source.params->GetMatrix());
    CaptureWindowRecordSurfaces(*curCanvas, drawable, screenParams, params, *source.renderDrawable, config);
}

} // namespace OHOS::Rosen::DrawableV2
