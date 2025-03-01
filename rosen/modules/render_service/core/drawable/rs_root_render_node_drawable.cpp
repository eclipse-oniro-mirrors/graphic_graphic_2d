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

#include "drawable/rs_root_render_node_drawable.h"

#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/rs_root_render_node.h"
#include "platform/common/rs_log.h"
#include "rs_trace.h"

namespace OHOS::Rosen::DrawableV2 {
RSRootRenderNodeDrawable::Registrar RSRootRenderNodeDrawable::instance_;
RSRootRenderNodeDrawable::RSRootRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node)
    : RSCanvasRenderNodeDrawable(std::move(node))
{}

RSRenderNodeDrawable::Ptr RSRootRenderNodeDrawable::OnGenerate(std::shared_ptr<const RSRenderNode> node)
{
    return new RSRootRenderNodeDrawable(std::move(node));
}

void RSRootRenderNodeDrawable::OnDraw(Drawing::Canvas& canvas)
{
    RS_LOGD("RSRootRenderNodeDrawable::OnDraw node: %{public}" PRIu64, nodeId_);
    if (DrawOffscreenToBuffer(canvas)) {
        return;
    }
    RSCanvasRenderNodeDrawable::OnDraw(canvas);
}

void RSRootRenderNodeDrawable::OnCapture(Drawing::Canvas& canvas)
{
    RS_LOGD("RSRootRenderNodeDrawable::OnCapture node: %{public}" PRIu64, nodeId_);

    RSCanvasRenderNodeDrawable::OnCapture(canvas);
}

bool RSRootRenderNodeDrawable::DrawOffscreenToBuffer(Drawing::Canvas& canvas)
{
    const auto& params = GetRenderParams();
    auto& uniParams = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (params == nullptr || uniParams == nullptr) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer renderParams or uniParams is nullptr");
        return false;
    }
    if (!params->GetNeedOffscreen()) {
        cachedOffscreenImg_ = nullptr;
        preCachedOffscreenImg_ = nullptr;
        return false;
    }

    auto curCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    auto curSurface = curCanvas->GetSurface();
    if (curSurface == nullptr) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer surface is nullptr");
        return false;
    }

    auto bounds = params->GetFrameRect();
    auto cacheSurface = curSurface->MakeSurface(bounds.GetWidth(), bounds.GetHeight());
    if (cacheSurface == nullptr) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer make surface failed");
        return false;
    }
    auto cacheCanvas = std::make_shared<RSPaintFilterCanvas>(cacheSurface.get());
    if (cacheCanvas == nullptr) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer make canvas failed");
        return false;
    }

    // Copy HDR properties into offscreen canvas
    cacheCanvas->CopyHDRConfiguration(*curCanvas);

    // Copy current canvas properties into offscreen canvas
    cacheCanvas->CopyConfigurationToOffscreenCanvas(*curCanvas);
    cacheCanvas->SetDisableFilterCache(true);
    auto acr = std::make_unique<RSAutoCanvasRestore>(cacheCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);
    cacheCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);

    bool isOpDropped = uniParams->IsOpDropped();
    uniParams->SetOpDropped(false); // temporarily close partial render
    RSCanvasRenderNodeDrawable::OnDraw(*cacheCanvas);
    uniParams->SetOpDropped(isOpDropped);
    params->ApplyAlphaAndMatrixToCanvas(*curCanvas, true);

    return DrawOffscreenImgToBuffer(canvas, *params, bounds, cacheSurface);
}

bool RSRootRenderNodeDrawable::DrawOffscreenImgToBuffer(Drawing::Canvas& canvas, const RSRenderParams& params,
    const Drawing::Rect& bounds, std::shared_ptr<Drawing::Surface>& surface)
{
    // cache and draw snapshot of offscreen canvas onto target canvas
    if (params.GetNeedSwapBuffer()) {
        std::swap(cachedOffscreenImg_, preCachedOffscreenImg_);
    }

    cachedOffscreenImg_ = surface->GetImageSnapshot();
    if (cachedOffscreenImg_ == nullptr) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer get snapshot nullptr");
        return false;
    }

    if (preCachedOffscreenImg_ == nullptr && params.GetNeedSwapBuffer()) {
        preCachedOffscreenImg_ = cachedOffscreenImg_;
    }

    Drawing::Brush paint;
    paint.SetAntiAlias(true);
    canvas.AttachBrush(paint);
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::NEAREST, Drawing::MipmapMode::NONE);
    Drawing::Rect cacheBounds = params.GetCacheNodeFrameRect();
    if (!cacheBounds.IsEmpty()) {
        // keep aspect ratio for scale
        Drawing::Rect srcRect;
        srcRect.left_ = 0;
        srcRect.top_ = 0;
        if (bounds.GetWidth() * cacheBounds.GetHeight() / bounds.GetHeight() >= cacheBounds.GetWidth()) {
            srcRect.right_ = bounds.GetHeight() * cacheBounds.GetWidth() / cacheBounds.GetHeight();
            srcRect.bottom_ = bounds.GetHeight();
        } else {
            srcRect.right_ = bounds.GetWidth();
            srcRect.bottom_ = bounds.GetWidth() * cacheBounds.GetHeight() / cacheBounds.GetWidth();
        }
        canvas.DrawImageRect(*cachedOffscreenImg_, srcRect, cacheBounds, samplingOptions);
    } else {
        canvas.DrawImageRect(*cachedOffscreenImg_, bounds, samplingOptions);
    }
    canvas.DetachBrush();

    return true;
}

bool RSRootRenderNodeDrawable::DrawOffscreenBuffer(
    RSPaintFilterCanvas& canvas, const Drawing::Rect& bounds, float alpha, bool isFreezed)
{
    if (preCachedOffscreenImg_ == nullptr) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer preCachedOffscreenImg_ is nullptr");
        return false;
    }

    float rootWidth = 0.0f;
    float rootHeight = 0.0f;
    const auto& params = GetRenderParams();
    if (params != nullptr) {
        rootWidth = params->GetFrameRect().GetWidth();
        rootHeight = params->GetFrameRect().GetHeight();
    }

    RS_TRACE_NAME_FMT("DrawCacheNode rootNode:(%.0f, %.0f), canvasNode:(%.0f, %.0f) alpha:%.2f, freeze:%d",
        rootWidth, rootHeight, bounds.GetWidth(), bounds.GetHeight(), alpha, isFreezed);

    RSAutoCanvasRestore acr(&canvas);
    Drawing::Brush paint;
    paint.SetAntiAlias(true);
    canvas.AttachBrush(paint);
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::NEAREST, Drawing::MipmapMode::NONE);

    Drawing::Rect srcRect;
    srcRect.left_ = 0;
    srcRect.top_ = 0;
    int imgW = preCachedOffscreenImg_->GetWidth();
    int imgH = preCachedOffscreenImg_->GetHeight();
    if (imgW <= 0 || imgH <= 0 || bounds.IsEmpty()) {
        RS_LOGE("RSRootRenderNodeDrawable::DrawOffscreenToBuffer preCachedOffscreenImg size or bounds is invalid");
        return false;
    }

    // keep aspect ratio for scale
    if (imgW * bounds.GetHeight() / imgH >= bounds.GetWidth()) {
        srcRect.right_ = imgH * bounds.GetWidth() / bounds.GetHeight();
        srcRect.bottom_ = imgH;
    } else {
        srcRect.right_ = imgW;
        srcRect.bottom_ = imgW * bounds.GetHeight() / bounds.GetWidth();
    }
    canvas.DrawImageRect(*preCachedOffscreenImg_, srcRect, bounds, samplingOptions,
        Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT);
    canvas.DetachBrush();

    return true;
}

} // namespace OHOS::Rosen::DrawableV2
