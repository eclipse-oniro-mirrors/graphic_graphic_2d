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

#include "render/rs_high_performance_visual_engine.h"
#include "common/rs_optional_trace.h"

namespace OHOS {
namespace Rosen {

HveFilter& HveFilter::GetHveFilter()
{
    static HveFilter filter;
    return filter;
}

void HveFilter::ClearSurfaceNodeInfo()
{
    surfaceNodeInfo_.clear();
}

void HveFilter::PushSurfaceNodeInfo(SurfaceNodeInfo& surfaceNodeInfo)
{
    surfaceNodeInfo_.push_back(surfaceNodeInfo);
}

std::vector<SurfaceNodeInfo> HveFilter::GetSurfaceNodeInfo()
{
    return surfaceNodeInfo_;
}

int HveFilter::GetSurfaceNodeSize()
{
    return surfaceNodeInfo_.size();
}

std::shared_ptr<Drawing::Image> HveFilter::SampleLayer(RSPaintFilterCanvas& canvas, const Drawing::RectI& srcRect)
{
    auto drawingSurface = canvas.GetSurface();

    std::shared_ptr<Drawing::Image> snapshot;
    int widthUI = srcRect.GetWidth();
    int heightUI = srcRect.GetHeight();
    auto offscreenSurface = drawingSurface->MakeSurface(widthUI, heightUI);
    if (offscreenSurface == nullptr) {
        ClearSurfaceNodeInfo();
        return snapshot;
    }
    auto offscreenCanvas = std::make_shared<RSPaintFilterCanvas>(offscreenSurface.get());
    if (offscreenCanvas == nullptr) {
        ClearSurfaceNodeInfo();
        return snapshot;
    }

    std::vector<SurfaceNodeInfo> vecSurfaceNode = GetSurfaceNodeInfo();
    size_t surfaceNodeSize = vecSurfaceNode.size();
    RS_TRACE_NAME_FMT("surfaceNodeSize:%d", surfaceNodeSize);
    Drawing::RectI dstRect = Drawing::RectI(0, 0, widthUI, heightUI);

    for (size_t i = 0; i < surfaceNodeSize; i++) {
        auto surfaceImage = vecSurfaceNode[i].surfaceImage_;
        Drawing::Matrix rotateMatrix = vecSurfaceNode[i].matrix_;
        Drawing::Rect parmSrcRect = vecSurfaceNode[i].srcRect_;
        Drawing::Rect parmDstRect = vecSurfaceNode[i].dstRect_;

        if (surfaceImage == nullptr) {
            continue;
        }
        offscreenCanvas->Save();
        offscreenCanvas->Translate(-srcRect.GetLeft(), -srcRect.GetTop());
        offscreenCanvas->ConcatMatrix(rotateMatrix);
        offscreenCanvas->DrawImageRect(*surfaceImage, parmSrcRect, parmDstRect, Drawing::SamplingOptions(),
            Drawing::SrcRectConstraint::FAST_SRC_RECT_CONSTRAINT);
        offscreenCanvas->Restore();
    }
    ClearSurfaceNodeInfo();

    auto inputImage = drawingSurface->GetImageSnapshot();
    if (inputImage != nullptr) {
        offscreenCanvas->DrawImageRect(*inputImage, srcRect, dstRect, Drawing::SamplingOptions(),
            Drawing::SrcRectConstraint::FAST_SRC_RECT_CONSTRAINT);
    }

    snapshot = offscreenSurface->GetImageSnapshot();
    return snapshot;
}
} // namespace Rosen
} // namespace OHOS