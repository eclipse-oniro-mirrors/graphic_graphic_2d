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

#include "rs_draw_window_cache.h"

#include "drawable/rs_surface_render_node_drawable.h"
#include "pipeline/rs_main_thread.h"
#include "rs_uni_render_thread.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {

RSDrawWindowCache::~RSDrawWindowCache()
{
    ClearCache();
}

void RSDrawWindowCache::DrawAndCacheWindowContent(DrawableV2::RSSurfaceRenderNodeDrawable* surfaceDrawable,
    RSPaintFilterCanvas& canvas, const Drawing::Rect& bounds)
{
    if (surfaceDrawable == nullptr) {
        RS_LOGE("RSDrawWindowCache::DrawAndCacheWindowContent drawable nullptr.");
        return;
    }

    // prepare offscreen canvas
    auto mainSurface = canvas.GetSurface();
    if (mainSurface == nullptr) {
        RS_LOGE("RSDrawWindowCache::DrawAndCacheWindowContent main surface nullptr.");
        return;
    }
    auto windowSurface = mainSurface->MakeSurface(bounds.GetWidth(), bounds.GetHeight());
    if (windowSurface == nullptr) {
        RS_LOGE("RSDrawWindowCache::DrawAndCacheWindowContent surface nullptr.");
        return;
    }
    auto windowCanvas = std::make_shared<RSPaintFilterCanvas>(windowSurface.get());
    if (windowCanvas == nullptr) {
        RS_LOGE("RSDrawWindowCache::DrawAndCacheWindowContent canvas nullptr.");
        windowSurface = nullptr;
        return;
    }
    RS_TRACE_NAME_FMT("DrawAndCacheWindow node[%lld] %s", surfaceDrawable->GetId(), surfaceDrawable->GetName().c_str());
    // copy HDR properties into offscreen canvas
    windowCanvas->CopyHDRConfiguration(canvas);
    // copy current canvas properties into offscreen canvas
    windowCanvas->CopyConfigurationToOffscreenCanvas(canvas);
    windowCanvas->SetDisableFilterCache(true);
    auto acr = std::make_unique<RSAutoCanvasRestore>(windowCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);
    windowCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);

    // draw window content/children onto offscreen canvas
    auto& uniParams = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    bool isOpDropped = uniParams != nullptr ? uniParams->IsOpDropped() : true;
    if (uniParams) {
        uniParams->SetOpDropped(false); // temporarily close partial render
    }
    surfaceDrawable->DrawContent(*windowCanvas, bounds); // draw content
    surfaceDrawable->DrawChildren(*windowCanvas, bounds); // draw children
    if (uniParams) {
        uniParams->SetOpDropped(isOpDropped);
    }

    // cache and draw snapshot of offscreen canvas onto target canvas
    image_ = windowSurface->GetImageSnapshot();
    if (image_ == nullptr) {
        RS_LOGE("RSDrawWindowCache::DrawAndCacheWindowContent snapshot nullptr.");
        return;
    }
    Drawing::Brush paint;
    paint.SetAntiAlias(true);
    canvas.AttachBrush(paint);
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::NEAREST, Drawing::MipmapMode::NONE);
    canvas.DrawImage(*image_, 0, 0, samplingOptions);
    canvas.DetachBrush();
}

bool RSDrawWindowCache::DealWithCachedWindow(DrawableV2::RSSurfaceRenderNodeDrawable* surfaceDrawable,
    RSPaintFilterCanvas& canvas, RSSurfaceRenderParams& surfaceParams, RSRenderThreadParams& uniParam)
{
    if (surfaceDrawable == nullptr ||
        surfaceDrawable->HasCachedTexture() ||
        !HasCache()) {
        ClearCache();
        return false;
    }
    // Non-CrosNode not cache for uifirst need clear cahce
    if (!surfaceParams.IsCrossNode() && surfaceParams.GetUifirstNodeEnableParam() == MultiThreadCacheType::NONE) {
        ClearCache();
        return false;
    }
    // CrosNode no need to clear cache
    if (surfaceParams.IsCrossNode() && (uniParam.IsMirrorScreen() ||
        uniParam.IsFirstVisitCrossNodeDisplay() || uniParam.HasDisplayHdrOn())) {
        return false;
    }
    if (ROSEN_EQ(image_->GetWidth(), 0) || ROSEN_EQ(image_->GetHeight(), 0)) {
        RS_LOGE("RSDrawWindowCache::DealWithCachedWindow buffer size is zero.");
        return false;
    }
    RS_TRACE_NAME_FMT("DealWithCachedWindow node[%lld] %s",
        surfaceDrawable->GetId(), surfaceDrawable->GetName().c_str());
    RSAutoCanvasRestore acr(&canvas);
    if (!RSUniRenderThread::GetCaptureParam().isSnapshot_) {
        canvas.MultiplyAlpha(surfaceParams.GetAlpha());
        canvas.ConcatMatrix(surfaceParams.GetMatrix());
    }
    if (surfaceParams.GetGlobalPositionEnabled()) {
        auto matrix = surfaceParams.GetTotalMatrix();
        matrix.Translate(-surfaceDrawable->offsetX_, -surfaceDrawable->offsetY_);
        canvas.ConcatMatrix(matrix);
    }
    auto boundSize = surfaceParams.GetFrameRect();
    // draw background
    surfaceDrawable->DrawBackground(canvas, boundSize);
    const auto& gravityMatrix = surfaceDrawable->GetGravityMatrix(image_->GetWidth(), image_->GetHeight());
    if (RSMainThread::Instance()->GetDeviceType() == DeviceType::PC) {
        canvas.Scale(gravityMatrix.Get(Drawing::Matrix::SCALE_X), gravityMatrix.Get(Drawing::Matrix::SCALE_Y));
    } else {
        float scaleX = boundSize.GetWidth() / static_cast<float>(image_->GetWidth());
        float scaleY = boundSize.GetHeight() / static_cast<float>(image_->GetHeight());
        canvas.Scale(scaleX, scaleY);
    }
    if (RSSystemProperties::GetRecordingEnabled()) {
        if (image_->IsTextureBacked()) {
            RS_LOGI("RSDrawWindowCache::DealWithCachedWindow convert image from texture to raster image.");
            image_ = image_->MakeRasterImage();
        }
    }
    Drawing::Brush brush;
    canvas.AttachBrush(brush);
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    auto translateX = gravityMatrix.Get(Drawing::Matrix::TRANS_X);
    auto translateY = gravityMatrix.Get(Drawing::Matrix::TRANS_Y);
    // draw content/children
    canvas.DrawImage(*image_, translateX, translateY, samplingOptions);
    canvas.DetachBrush();
    // draw foreground
    surfaceDrawable->DrawForeground(canvas, boundSize);
    // draw watermark
    surfaceDrawable->DrawWatermark(canvas, surfaceParams);
    return true;
}

void RSDrawWindowCache::ClearCache()
{
    image_ = nullptr;
}

bool RSDrawWindowCache::HasCache() const
{
    return image_ != nullptr;
}

} // Rosen
} // OHOS