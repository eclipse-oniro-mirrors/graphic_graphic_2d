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

#include "drawable/rs_canvas_render_node_drawable.h"

#include "rs_trace.h"

#include "common/rs_optional_trace.h"
#include "pipeline/rs_canvas_render_node.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_uni_render_thread.h"
#include "platform/common/rs_log.h"
#include "utils/rect.h"
#include "utils/region.h"

namespace OHOS::Rosen::DrawableV2 {
RSCanvasRenderNodeDrawable::Registrar RSCanvasRenderNodeDrawable::instance_;

RSCanvasRenderNodeDrawable::RSCanvasRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node)
    : RSRenderNodeDrawable(std::move(node))
{}

RSRenderNodeDrawable::Ptr RSCanvasRenderNodeDrawable::OnGenerate(std::shared_ptr<const RSRenderNode> node)
{
    return new RSCanvasRenderNodeDrawable(std::move(node));
}

/*
 * This function will be called recursively many times, and the logic should be as concise as possible.
 */
void RSCanvasRenderNodeDrawable::OnDraw(Drawing::Canvas& canvas)
{
    if (!ShouldPaint()) {
        return;
    }
    const auto& params = GetRenderParams();
    if (params == nullptr) {
        RS_LOGE("RSCanvasRenderNodeDrawable::OnDraw params is null, id:%{public}" PRIu64 "", nodeId_);
        return;
    }
    auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    if (params->GetStartingWindowFlag() && paintFilterCanvas) { // do not draw startingwindows in sudthread
        if (paintFilterCanvas->GetIsParallelCanvas()) {
            RS_LOGI("RSCanvasRenderNodeDrawable::OnDraw do not draw startingwindow"
                " with parallel canvas, id:%{public}" PRIu64 "", nodeId_);
            return;
        }
    }
    auto isOpincDraw = PreDrawableCacheState(*params, isOpincDropNodeExt_);
    RSAutoCanvasRestore acr(paintFilterCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);
    params->ApplyAlphaAndMatrixToCanvas(*paintFilterCanvas);
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if ((UNLIKELY(!uniParam) || uniParam->IsOpDropped()) && GetOpDropped() &&
        QuickReject(canvas, params->GetLocalDrawRect()) && isOpincDraw) {
        RS_LOGI("RSCanvasRenderNodeDrawable::OnDraw IsOpDropped = %{public}d, "
        "GetOpDropped = %{public}d, isOpincDraw = %{public}d, id:%{public}" PRIu64 "",
            uniParam->IsOpDropped(), GetOpDropped(), isOpincDraw, nodeId_);
        return;
    }

    if (LIKELY(isDrawingCacheEnabled_)) {
        BeforeDrawCache(nodeCacheType_, canvas, *params, isOpincDropNodeExt_);
        if (!drawBlurForCache_) {
            GenerateCacheIfNeed(canvas, *params);
        }
        CheckCacheTypeAndDraw(canvas, *params);
        AfterDrawCache(nodeCacheType_, canvas, *params, isOpincDropNodeExt_, opincRootTotalCount_);
    } else {
        RSRenderNodeDrawable::OnDraw(canvas);
    }
    RSRenderNodeDrawable::ProcessedNodeCountInc();
}

/*
 * This function will be called recursively many times, and the logic should be as concise as possible.
 */
void RSCanvasRenderNodeDrawable::OnCapture(Drawing::Canvas& canvas)
{
    if (!ShouldPaint()) {
        return;
    }
    const auto& params = GetRenderParams();
    auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    RSAutoCanvasRestore acr(paintFilterCanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);
    params->ApplyAlphaAndMatrixToCanvas(*paintFilterCanvas);

    if (LIKELY(isDrawingCacheEnabled_)) {
        if (canvas.GetUICapture() && !drawBlurForCache_) {
            GenerateCacheIfNeed(canvas, *params);
        }
        CheckCacheTypeAndDraw(canvas, *params, true);
    } else {
        RSRenderNodeDrawable::OnDraw(canvas);
    }
}
} // namespace OHOS::Rosen::DrawableV2
