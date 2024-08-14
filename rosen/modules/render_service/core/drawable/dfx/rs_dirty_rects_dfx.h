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

#ifndef RENDER_SERVICE_DRAWABLE_DFX_RS_DIRTY_RECTS_DFX_H
#define RENDER_SERVICE_DRAWABLE_DFX_RS_DIRTY_RECTS_DFX_H

#include <string>

#include "system/rs_system_parameters.h"

#include "common/rs_occlusion_region.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "params/rs_render_params.h"
#include "params/rs_render_thread_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_recording_canvas.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_uni_render_thread.h"
namespace OHOS::Rosen {

class RSDirtyRectsDfx {
public:
    explicit RSDirtyRectsDfx(DrawableV2::RSDisplayRenderNodeDrawable& targetDrawable)
        : targetDrawable_(targetDrawable), displayParams_(targetDrawable.GetRenderParams())
    {}
    ~RSDirtyRectsDfx() = default;

    enum class RSPaintStyle { FILL, STROKE };
    void OnDraw(std::shared_ptr<RSPaintFilterCanvas> canvas);
    void OnDrawVirtual(std::shared_ptr<RSPaintFilterCanvas> canvas);
    void SetDirtyRegion(Occlusion::Region& dirtyRegion)
    {
        dirtyRegion_ = dirtyRegion;
    }

    void SetVirtualDirtyRects(const std::vector<RectI>& virtualDirtyRects, const ScreenInfo& screenInfo)
    {
        virtualDirtyRects_ = virtualDirtyRects;
        screenInfo_ = screenInfo;
    }

private:
    Occlusion::Region dirtyRegion_;
    std::vector<RectI> virtualDirtyRects_;
    ScreenInfo screenInfo_;
    const DrawableV2::RSDisplayRenderNodeDrawable& targetDrawable_;
    std::shared_ptr<RSPaintFilterCanvas> canvas_;
    const std::unique_ptr<RSRenderParams>& displayParams_;

    bool RefreshRateRotationProcess(ScreenRotation rotation, uint64_t screenId);
    void DrawCurrentRefreshRate();
    void DrawDirtyRectForDFX(RectI dirtyRect, const Drawing::Color color, const RSPaintStyle fillType,
        float alpha, int edgeWidth = 6) const;
    bool DrawDetailedTypesOfDirtyRegionForDFX(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable) const;
    void DrawSurfaceOpaqueRegionForDFX(RSSurfaceRenderParams& surfaceParams) const;
    void DrawHwcRegionForDFX() const;

    void DrawDirtyRegionForDFX(const std::vector<RectI>& dirtyRects) const;
    void DrawAllSurfaceDirtyRegionForDFX() const;
    void DrawAllSurfaceOpaqueRegionForDFX() const;
    void DrawTargetSurfaceDirtyRegionForDFX() const;
    void DrawTargetSurfaceVisibleRegionForDFX() const;
    void DrawAndTraceSingleDirtyRegionTypeForDFX(
        DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable, DirtyRegionType dirtyType, bool isDrawn = true) const;
    void DrawDirtyRegionInVirtual() const;

    // dfx check if surface name is in dfx target list
    inline bool CheckIfSurfaceTargetedForDFX(std::string nodeName) const
    {
        auto surfaceName = RSUniRenderThread::Instance().GetRSRenderThreadParams()->dfxTargetSurfaceNames_;
        return (std::find(surfaceName.begin(), surfaceName.end(), nodeName) != surfaceName.end());
    }
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_DRAWABLE_DFX_RS_DIRTY_RECTS_DFX_H
