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

#include <cstdint>
#include <sys/types.h>
#include <parameters.h>

#include "rs_dirty_rects_dfx.h"
#include "rs_trace.h"

#include "drawable/rs_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "params/rs_surface_render_params.h"
#include "platform/common/rs_log.h"
#include "screen_manager/rs_screen_manager.h"

// fresh rate
#include "hgm_core.h"

#include "pipeline/hardware_thread/rs_realtime_refresh_rate_manager.h"
#include "pipeline/render_thread/rs_uni_render_util.h"

namespace OHOS::Rosen {
namespace {
// DFX drawing alpha
constexpr float DFXFillAlpha = 0.2f;
constexpr float DFXFontSize = 24.f;
constexpr float HWC_DFX_FILL_ALPHA = 0.3f;
}

static const std::map<DirtyRegionType, std::string> DIRTY_REGION_TYPE_MAP {
    { DirtyRegionType::UPDATE_DIRTY_REGION, "UPDATE_DIRTY_REGION" },
    { DirtyRegionType::OVERLAY_RECT, "OVERLAY_RECT" },
    { DirtyRegionType::FILTER_RECT, "FILTER_RECT" },
    { DirtyRegionType::SHADOW_RECT, "SHADOW_RECT" },
    { DirtyRegionType::PREPARE_CLIP_RECT, "PREPARE_CLIP_RECT" },
    { DirtyRegionType::REMOVE_CHILD_RECT, "REMOVE_CHILD_RECT" },
    { DirtyRegionType::RENDER_PROPERTIES_RECT, "RENDER_PROPERTIES_RECT" },
    { DirtyRegionType::CANVAS_NODE_SKIP_RECT, "CANVAS_NODE_SKIP_RECT" },
    { DirtyRegionType::OUTLINE_RECT, "OUTLINE_RECT" },
    { DirtyRegionType::SUBTREE_SKIP_RECT, "SUBTREE_SKIP_RECT" },
    { DirtyRegionType::SUBTREE_SKIP_OUT_OF_PARENT_RECT, "SUBTREE_SKIP_OUT_OF_PARENT_RECT" },
};

void RSDirtyRectsDfx::OnDraw(RSPaintFilterCanvas& canvas)
{
    auto& renderThreadParams = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (UNLIKELY(!renderThreadParams)) {
        RS_LOGE("RSDirtyRectsDfx::OnDraw render thread params is nullptr!");
        return;
    }

    // the following code makes DirtyRegion visible, enable this method by turning on the dirtyregiondebug property
    if (renderThreadParams->isPartialRenderEnabled_) {
        if (renderThreadParams->isDirtyRegionDfxEnabled_) {
            DrawAllSurfaceDirtyRegionForDFX(canvas);
        }
        if (renderThreadParams->isTargetDirtyRegionDfxEnabled_) {
            DrawTargetSurfaceDirtyRegionForDFX(canvas);
        }
        if (renderThreadParams->isDisplayDirtyDfxEnabled_) {
            DrawDirtyRegionForDFX(canvas, targetDrawable_.GetSyncDirtyManager()->GetMergedDirtyRegions());
        }
    }

    if (renderThreadParams->isOpaqueRegionDfxEnabled_) {
        DrawAllSurfaceOpaqueRegionForDFX(canvas);
    }
    if (renderThreadParams->isVisibleRegionDfxEnabled_) {
        DrawTargetSurfaceVisibleRegionForDFX(canvas);
    }

    if (RSRealtimeRefreshRateManager::Instance().GetShowRefreshRateEnabled()) {
        DrawCurrentRefreshRate(canvas);
    }

    if (RSSystemProperties::GetHwcRegionDfxEnabled()) {
        DrawHwcRegionForDFX(canvas);
    }

    DrawableV2::RSRenderNodeDrawable::DrawDfxForCacheInfo(canvas);
}

void RSDirtyRectsDfx::OnDrawVirtual(RSPaintFilterCanvas& canvas)
{
    auto& renderThreadParams = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (UNLIKELY(!renderThreadParams)) {
        RS_LOGE("RSDirtyRectsDfx::OnDraw render thread params is nullptr!");
        return;
    }

    if (renderThreadParams->isVirtualDirtyDfxEnabled_) {
        DrawDirtyRegionInVirtual(canvas);
    }
}

void RSDirtyRectsDfx::DrawHwcRegionForDFX(RSPaintFilterCanvas& canvas) const
{
#ifdef RS_ENABLE_GPU
    auto& hardwareDrawables =
        RSUniRenderThread::Instance().GetRSRenderThreadParams()->GetHardwareEnabledTypeDrawables();
    static uint32_t updateCnt = 0;
    if (++updateCnt == UINT32_MAX) {
        updateCnt = 0;
    }
    for (const auto& [_, drawable] : hardwareDrawables) {
        if (UNLIKELY(!drawable || !drawable->GetRenderParams())) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
        std::string extraInfo = surfaceParams->GetName() + " UpdateCnt: " + std::to_string(updateCnt);
        if (surfaceParams->GetHardwareEnabled()) {
            RSUniRenderUtil::DrawRectForDfx(canvas, surfaceParams->GetDstRect(), Drawing::Color::COLOR_BLUE,
                HWC_DFX_FILL_ALPHA, extraInfo);
        } else {
            RSUniRenderUtil::DrawRectForDfx(canvas, surfaceParams->GetDstRect(), Drawing::Color::COLOR_RED,
                HWC_DFX_FILL_ALPHA, extraInfo);
        }
    }
#endif
}

void RSDirtyRectsDfx::DrawDirtyRegionInVirtual(RSPaintFilterCanvas& canvas) const
{
    for (const auto& subRect : virtualDirtyRects_) {
        RectI tmpRect;
#ifdef RS_ENABLE_VK
        if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
            RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
            tmpRect = subRect;
        } else {
            tmpRect = RectI(subRect.GetLeft(),
                static_cast<int32_t>(screenInfo_.GetRotatedHeight()) - subRect.GetTop() - subRect.GetHeight(),
                subRect.GetWidth(), subRect.GetHeight());
        }
#else
        tmpRect = RectI(subRect.GetLeft(),
            static_cast<int32_t>(screenInfo_.GetRotatedHeight()) - subRect.GetTop() - subRect.GetHeight(),
            subRect.GetWidth(), subRect.GetHeight());
#endif
        DrawDirtyRectForDFX(canvas, tmpRect, Drawing::Color::COLOR_BLUE, RSPaintStyle::STROKE);
    }
}

bool RSDirtyRectsDfx::RefreshRateRotationProcess(RSPaintFilterCanvas& canvas,
    ScreenRotation rotation, int translateWidth, int translateHeight)
{
    auto screenManager = CreateOrGetScreenManager();
    if (UNLIKELY(displayParams_ == nullptr || screenManager == nullptr)) {
        return false;
    }
    auto screenId = displayParams_->GetScreenId();
    auto screenCorrection = screenManager->GetScreenCorrection(screenId);
    if (screenCorrection != ScreenRotation::INVALID_SCREEN_ROTATION &&
        screenCorrection != ScreenRotation::ROTATION_0) {
        // Recaculate rotation if mirrored screen has additional rotation angle
        rotation = static_cast<ScreenRotation>((static_cast<int>(rotation) + SCREEN_ROTATION_NUM
            - static_cast<int>(screenCorrection)) % SCREEN_ROTATION_NUM);
    }
    if (rotation == ScreenRotation::ROTATION_90 || rotation == ScreenRotation::ROTATION_270) {
        std::swap(translateWidth, translateHeight);
    }

    if (rotation != ScreenRotation::ROTATION_0) {
        if (rotation == ScreenRotation::ROTATION_90) {
            canvas.Rotate(-90, 0, 0); // 90 degree for text draw
            canvas.Translate(-(static_cast<float>(translateWidth)), 0);
        } else if (rotation == ScreenRotation::ROTATION_180) {
            // 180 degree for text draw
            canvas.Rotate(-180, static_cast<float>(translateWidth) / 2, // 2 half of screen width
                static_cast<float>(translateHeight) / 2);                 // 2 half of screen height
        } else if (rotation == ScreenRotation::ROTATION_270) {
            canvas.Rotate(-270, 0, 0); // 270 degree for text draw
            canvas.Translate(0, -(static_cast<float>(translateHeight)));
        } else {
            return false;
        }
    }
    return true;
}

void RSDirtyRectsDfx::DrawCurrentRefreshRate(RSPaintFilterCanvas& canvas)
{
    RS_TRACE_FUNC();
    if (UNLIKELY(!displayParams_)) {
        return;
    }
    auto screenId = displayParams_->GetScreenId();
    static const std::string FOLD_SCREEN_TYPE = system::GetParameter("const.window.foldscreen.type", "0,0,0,0");
    const char dualDisplay = '2';
    // fold device with two logic screens
    if ((FOLD_SCREEN_TYPE[0] == dualDisplay) && screenId != 0) {
        return;
    }
    uint32_t currentRefreshRate = OHOS::Rosen::HgmCore::Instance().GetScreenCurrentRefreshRate(screenId);
    uint32_t realtimeRefreshRate = RSRealtimeRefreshRateManager::Instance().GetRealtimeRefreshRate(screenId);
    static bool showRealtimeRefreshRate = system::GetParameter("const.logsystem.versiontype", "") == "beta";
    std::string info = std::to_string(currentRefreshRate);
    if (showRealtimeRefreshRate || RSSystemParameters::GetShowRefreshRateEnabled()) {
        info += " " + std::to_string(realtimeRefreshRate);
    }
    std::shared_ptr<Drawing::Typeface> tf = Drawing::Typeface::MakeFromName("HarmonyOS Sans SC", Drawing::FontStyle());
    Drawing::Font font;
    font.SetSize(100); // 100:Scalar of setting font size
    font.SetTypeface(tf);
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromString(info.c_str(), font);

    Drawing::Brush brush;
    brush.SetColor(currentRefreshRate <= 60 ? SK_ColorRED : SK_ColorGREEN); // low refresh rate 60
    brush.SetAntiAlias(true);
    RSAutoCanvasRestore acr(&canvas);
    canvas.AttachBrush(brush);
    auto rotation = displayParams_->GetScreenRotation();
    auto screenManager = CreateOrGetScreenManager();
    if (screenManager == nullptr) {
        return;
    }
    auto screenInfo = screenManager->QueryScreenInfo(screenId);
    auto screenWidth = screenInfo.width;
    auto screenHeight = screenInfo.height;
    auto activeRect = screenInfo.activeRect;
    if (!activeRect.IsEmpty()) {
        canvas.Translate(activeRect.left_, activeRect.top_);
        screenWidth = static_cast<uint32_t>(activeRect.width_);
        screenHeight = static_cast<uint32_t>(activeRect.height_);
    }
    auto saveCount = canvas.Save();
    if (!RefreshRateRotationProcess(canvas, rotation, screenWidth, screenHeight)) {
        return;
    }
    // 100.f:Scalar x of drawing TextBlob; 200.f:Scalar y of drawing TextBlob
    canvas.DrawTextBlob(textBlob.get(), 100.f, 200.f);
    canvas.RestoreToCount(saveCount);
    canvas.DetachBrush();
}

void RSDirtyRectsDfx::DrawDirtyRectForDFX(RSPaintFilterCanvas& canvas, RectI dirtyRect, const Drawing::Color color,
    const RSPaintStyle fillType, int edgeWidth, bool isTextOutsideRect) const
{
    if (dirtyRect.width_ <= 0 || dirtyRect.height_ <= 0) {
        ROSEN_LOGD("DrawDirtyRectForDFX dirty rect is invalid.");
        return;
    }
    ROSEN_LOGD("DrawDirtyRectForDFX current dirtyRect = %{public}s", dirtyRect.ToString().c_str());
    auto rect = Drawing::Rect(
        dirtyRect.left_, dirtyRect.top_, dirtyRect.left_ + dirtyRect.width_, dirtyRect.top_ + dirtyRect.height_);
    RSAutoCanvasRestore acr(&canvas);
    Drawing::Matrix invertMatrix;
    if (displayParams_ && displayParams_->GetMatrix().Invert(invertMatrix)) {
        // Modifying the drawing origin does not affect the actual drawing content
        canvas.ConcatMatrix(displayParams_->GetMatrix());
        invertMatrix.MapRect(rect, rect);
        dirtyRect.SetAll(rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
    }
    std::string position = std::to_string(dirtyRect.left_) + ',' + std::to_string(dirtyRect.top_) + ',' +
                           std::to_string(dirtyRect.width_) + ',' + std::to_string(dirtyRect.height_);
    const int defaultTextOffsetX = edgeWidth;
    const int defaultTextOffsetY = 30; // text position has 30 pixelSize under the Rect
    Drawing::Pen rectPen;
    Drawing::Brush rectBrush;
    // font size: 24
    std::shared_ptr<Drawing::TextBlob> textBlob =
        Drawing::TextBlob::MakeFromString(position.c_str(), Drawing::Font(nullptr, DFXFontSize, 1.0f, 0.0f));
    if (fillType == RSPaintStyle::STROKE) {
        rectPen.SetColor(color);
        rectPen.SetAntiAlias(true);
        rectPen.SetAlphaF(DFXFillAlpha);
        rectPen.SetWidth(edgeWidth);
        rectPen.SetJoinStyle(Drawing::Pen::JoinStyle::ROUND_JOIN);
        canvas.AttachPen(rectPen);
    } else {
        rectBrush.SetColor(color);
        rectBrush.SetAntiAlias(true);
        rectBrush.SetAlphaF(DFXFillAlpha);
        canvas.AttachBrush(rectBrush);
    }
    canvas.DrawRect(rect);
    canvas.DetachPen();
    canvas.DetachBrush();
    canvas.AttachBrush(Drawing::Brush());
    if (isTextOutsideRect) {
        canvas.DrawTextBlob(textBlob.get(), dirtyRect.left_ + defaultTextOffsetX, dirtyRect.top_ - edgeWidth);
    } else {
        canvas.DrawTextBlob(textBlob.get(), dirtyRect.left_ + defaultTextOffsetX, dirtyRect.top_ + defaultTextOffsetY);
    }
    canvas.DetachBrush();
}

void RSDirtyRectsDfx::DrawDirtyRegionForDFX(RSPaintFilterCanvas& canvas, const std::vector<RectI>& dirtyRects) const
{
    for (const auto& subRect : dirtyRects) {
        DrawDirtyRectForDFX(canvas, subRect, Drawing::Color::COLOR_BLUE, RSPaintStyle::STROKE);
    }
}

void RSDirtyRectsDfx::DrawAndTraceSingleDirtyRegionTypeForDFX(RSPaintFilterCanvas& canvas,
    DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable, DirtyRegionType dirtyType, bool isDrawn) const
{
    auto dirtyManager = surfaceDrawable.GetSyncDirtyManager();
    auto matchType = DIRTY_REGION_TYPE_MAP.find(dirtyType);
    if (matchType == DIRTY_REGION_TYPE_MAP.end()) {
        return;
    }
    std::map<NodeId, RectI> dirtyInfo;
    std::map<RSRenderNodeType, std::pair<std::string, SkColor>> nodeConfig = {
        { RSRenderNodeType::CANVAS_NODE, std::make_pair("canvas", SK_ColorRED) },
        { RSRenderNodeType::SURFACE_NODE, std::make_pair("surface", SK_ColorGREEN) },
    };

    std::string subInfo;
    for (const auto& [nodeType, info] : nodeConfig) {
        dirtyManager->GetDirtyRegionInfo(dirtyInfo, nodeType, dirtyType);
        subInfo += (" " + info.first + "node amount: " + std::to_string(dirtyInfo.size()));
        for (const auto& [nid, rect] : dirtyInfo) {
            if (isDrawn) {
                DrawDirtyRectForDFX(canvas, rect, info.second, RSPaintStyle::STROKE);
            }
        }
    }
    RS_TRACE_NAME_FMT("DrawAndTraceSingleDirtyRegionTypeForDFX target surface node %s - id[%" PRIu64 "]"
        " has dirtytype %s %s", surfaceDrawable.GetName().c_str(), surfaceDrawable.GetId(),
        matchType->second.c_str(), subInfo.c_str());
    ROSEN_LOGD("DrawAndTraceSingleDirtyRegionTypeForDFX target surface node %{public}s, id[%{public}" PRIu64 "]"
        "has dirtytype %{public}s%{public}s",
        surfaceDrawable.GetName().c_str(), surfaceDrawable.GetId(), matchType->second.c_str(), subInfo.c_str());
}

bool RSDirtyRectsDfx::DrawDetailedTypesOfDirtyRegionForDFX(RSPaintFilterCanvas& canvas,
    DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable) const
{
    auto dirtyRegionDebugType = RSUniRenderThread::Instance().GetRSRenderThreadParams()->dirtyRegionDebugType_;
    if (dirtyRegionDebugType < DirtyRegionDebugType::CUR_DIRTY_DETAIL_ONLY_TRACE) {
        return false;
    }
    if (dirtyRegionDebugType == DirtyRegionDebugType::CUR_DIRTY_DETAIL_ONLY_TRACE) {
        auto i = DirtyRegionType::UPDATE_DIRTY_REGION;
        for (; i < DirtyRegionType::TYPE_AMOUNT; i = static_cast<DirtyRegionType>(i + 1)) {
            DrawAndTraceSingleDirtyRegionTypeForDFX(canvas, surfaceDrawable, i, false);
        }
        return true;
    }
    static const std::map<DirtyRegionDebugType, DirtyRegionType> DIRTY_REGION_DEBUG_TYPE_MAP {
        { DirtyRegionDebugType::UPDATE_DIRTY_REGION, DirtyRegionType::UPDATE_DIRTY_REGION },
        { DirtyRegionDebugType::OVERLAY_RECT, DirtyRegionType::OVERLAY_RECT },
        { DirtyRegionDebugType::FILTER_RECT, DirtyRegionType::FILTER_RECT },
        { DirtyRegionDebugType::SHADOW_RECT, DirtyRegionType::SHADOW_RECT },
        { DirtyRegionDebugType::PREPARE_CLIP_RECT, DirtyRegionType::PREPARE_CLIP_RECT },
        { DirtyRegionDebugType::REMOVE_CHILD_RECT, DirtyRegionType::REMOVE_CHILD_RECT },
        { DirtyRegionDebugType::RENDER_PROPERTIES_RECT, DirtyRegionType::RENDER_PROPERTIES_RECT },
        { DirtyRegionDebugType::CANVAS_NODE_SKIP_RECT, DirtyRegionType::CANVAS_NODE_SKIP_RECT },
        { DirtyRegionDebugType::OUTLINE_RECT, DirtyRegionType::OUTLINE_RECT },
        { DirtyRegionDebugType::SUBTREE_SKIP_OUT_OF_PARENT_RECT, DirtyRegionType::SUBTREE_SKIP_OUT_OF_PARENT_RECT },
    };
    auto matchType = DIRTY_REGION_DEBUG_TYPE_MAP.find(dirtyRegionDebugType);
    if (matchType != DIRTY_REGION_DEBUG_TYPE_MAP.end()) {
        DrawAndTraceSingleDirtyRegionTypeForDFX(canvas, surfaceDrawable, matchType->second);
    }
    return true;
}
#ifdef RS_ENABLE_GPU
void RSDirtyRectsDfx::DrawSurfaceOpaqueRegionForDFX(RSPaintFilterCanvas& canvas,
    RSSurfaceRenderParams& surfaceParams) const
{
    if (!displayParams_) {
        return;
    }
    auto params = static_cast<RSDisplayRenderParams*>(displayParams_.get());
    if (surfaceParams.IsFirstLevelCrossNode() && !params->IsFirstVisitCrossNodeDisplay()) {
        return;
    }
    const auto& opaqueRegionRects = surfaceParams.GetOpaqueRegion().GetRegionRects();
    for (const auto& subRect : opaqueRegionRects) {
        DrawDirtyRectForDFX(canvas, subRect.ToRectI(), Drawing::Color::COLOR_GREEN, RSPaintStyle::FILL, 0);
    }
}
#endif
void RSDirtyRectsDfx::DrawAllSurfaceDirtyRegionForDFX(RSPaintFilterCanvas& canvas) const
{
    const auto& visibleDirtyRects = dirtyRegion_.GetRegionRects();
    std::vector<RectI> rects;
    for (auto& rect : visibleDirtyRects) {
        rects.emplace_back(rect.left_, rect.top_, rect.right_ - rect.left_, rect.bottom_ - rect.top_);
    }
    DrawDirtyRegionForDFX(canvas, rects);

    // draw expanded dirtyregion with cyan color
    constexpr int edgeWidth = 6;
    for (const auto& subRect : expandedDirtyRegion_.GetRegionRectIs()) {
        DrawDirtyRectForDFX(canvas, subRect, Drawing::Color::COLOR_CYAN, RSPaintStyle::STROKE, edgeWidth, true);
    }
}

void RSDirtyRectsDfx::DrawAllSurfaceOpaqueRegionForDFX(RSPaintFilterCanvas& canvas) const
{
#ifdef RS_ENABLE_GPU
    if (!displayParams_) {
        RS_LOGE("RSDirtyRectsDfx::DrawAllSurfaceOpaqueRegionForDFX displayParams is null ptr.");
        return;
    }
    auto& curAllSurfacesDrawables = displayParams_->GetAllMainAndLeashSurfaceDrawables();
    for (auto it = curAllSurfacesDrawables.rbegin(); it != curAllSurfacesDrawables.rend(); ++it) {
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>((*it)->GetRenderParams().get());
        if (surfaceParams && surfaceParams->IsMainWindowType()) {
            DrawSurfaceOpaqueRegionForDFX(canvas, *surfaceParams);
        }
    }
#endif
}

void RSDirtyRectsDfx::DrawTargetSurfaceDirtyRegionForDFX(RSPaintFilterCanvas& canvas) const
{
    if (UNLIKELY(!displayParams_)) {
        return;
    }
    const auto& curAllSurfaceDrawables = displayParams_->GetAllMainAndLeashSurfaceDrawables();
    for (const auto& drawable : curAllSurfaceDrawables) {
        if (UNLIKELY(!drawable)) {
            continue;
        }
        auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
        auto& surfaceParams = surfaceDrawable->GetRenderParams();
        if (UNLIKELY(!surfaceParams) || !surfaceParams->IsAppWindow()) {
            continue;
        }
        if (CheckIfSurfaceTargetedForDFX(surfaceDrawable->GetName())) {
            if (DrawDetailedTypesOfDirtyRegionForDFX(canvas, *surfaceDrawable)) {
                continue;
            }
            auto dirtyManager = targetDrawable_.GetSyncDirtyManager();
            const auto& visibleDirtyRects = surfaceDrawable->GetVisibleDirtyRegion().GetRegionRects();
            std::vector<RectI> rects;
            for (auto& rect : visibleDirtyRects) {
                rects.emplace_back(rect.left_, rect.top_, rect.right_ - rect.left_, rect.bottom_ - rect.top_);
            }
            const auto visibleRects = surfaceParams->GetVisibleRegion().GetRegionRects();
            auto displayDirtyRegion = dirtyManager->GetDirtyRegion();
            for (auto& rect : visibleRects) {
                auto visibleRect = RectI(rect.left_, rect.top_, rect.right_ - rect.left_, rect.bottom_ - rect.top_);
                auto intersectRegion = displayDirtyRegion.IntersectRect(visibleRect);
                rects.emplace_back(intersectRegion);
            }
            DrawDirtyRegionForDFX(canvas, rects);
        }
    }
}

void RSDirtyRectsDfx::DrawTargetSurfaceVisibleRegionForDFX(RSPaintFilterCanvas& canvas) const
{
#ifdef RS_ENABLE_GPU
    if (!displayParams_) {
        RS_LOGE("RSDirtyRectsDfx: displayParams is null ptr.");
        return;
    }
    auto& curAllSurfacesDrawables = displayParams_->GetAllMainAndLeashSurfaceDrawables();
    for (auto it = curAllSurfacesDrawables.rbegin(); it != curAllSurfacesDrawables.rend(); ++it) {
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>((*it)->GetRenderParams().get());
        if (surfaceParams == nullptr || !surfaceParams->IsAppWindow()) {
            continue;
        }
        if (CheckIfSurfaceTargetedForDFX(surfaceParams->GetName())) {
            const auto visibleRects = surfaceParams->GetVisibleRegion().GetRegionRects();
            std::vector<RectI> rects;
            for (auto& rect : visibleRects) {
                rects.emplace_back(rect.left_, rect.top_, rect.right_ - rect.left_, rect.bottom_ - rect.top_);
            }
            DrawDirtyRegionForDFX(canvas, rects);
        }
    }
#endif
}

} // namespace OHOS::Rosen