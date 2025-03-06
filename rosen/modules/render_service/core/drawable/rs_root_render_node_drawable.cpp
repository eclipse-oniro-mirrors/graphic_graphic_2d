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

namespace OHOS::Rosen::DrawableV2 {
RSRootRenderNodeDrawable::Registrar RSRootRenderNodeDrawable::instance_;
RSRootRenderNodeDrawable::RSRootRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node)
    : RSCanvasRenderNodeDrawable(std::move(node)), windowKeyframeBuffer_(*this)
{}

RSRenderNodeDrawable::Ptr RSRootRenderNodeDrawable::OnGenerate(std::shared_ptr<const RSRenderNode> node)
{
    return new RSRootRenderNodeDrawable(std::move(node));
}

void RSRootRenderNodeDrawable::OnDraw(Drawing::Canvas& canvas)
{
    RS_LOGD("RSRootRenderNodeDrawable::OnDraw node: %{public}" PRIu64, nodeId_);

    // for PC app window size changed by drag
    if (UNLIKELY(windowKeyframeBuffer_.OnDraw(canvas))) {
        return;
    }

    RSCanvasRenderNodeDrawable::OnDraw(canvas);
}

void RSRootRenderNodeDrawable::OnCapture(Drawing::Canvas& canvas)
{
    RS_LOGD("RSRootRenderNodeDrawable::OnCapture node: %{public}" PRIu64, nodeId_);

    RSCanvasRenderNodeDrawable::OnCapture(canvas);
}

bool RSRootRenderNodeDrawable::DrawOffscreenBuffer(
    RSPaintFilterCanvas& canvas, const Drawing::Rect& bounds, float alpha, bool isFreezed)
{
    return windowKeyframeBuffer_.DrawOffscreenBuffer(canvas, bounds, alpha, isFreezed);
}

} // namespace OHOS::Rosen::DrawableV2
