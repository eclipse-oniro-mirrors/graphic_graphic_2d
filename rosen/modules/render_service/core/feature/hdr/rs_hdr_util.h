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

#ifndef RS_HDR_UTIL_H
#define RS_HDR_UTIL_H

#include "params/rs_screen_render_params.h"
#include "pipeline/render_thread/rs_base_render_engine.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_surface_render_node.h"

namespace OHOS {
namespace Rosen {
class RSScreenManager;

namespace RSHDRUtilConst {
#ifdef USE_VIDEO_PROCESSING_ENGINE
    using namespace HDI::Display::Graphic::Common::V1_0;
    const CM_ColorSpaceInfo HDR_CAST_IN_COLORSPACE = {
        .primaries = COLORPRIMARIES_SRGB,
        .transfunc = TRANSFUNC_SRGB,
        .matrix = MATRIX_BT601_N,
        .range = RANGE_FULL,
    };
    const CM_ColorSpaceInfo HDR_CAST_OUT_COLORSPACE = {
        .primaries = COLORPRIMARIES_BT2020,
        .transfunc = TRANSFUNC_HLG,
        .matrix = MATRIX_BT2020,
        .range = RANGE_FULL,
    };
    constexpr CM_ColorSpaceInfo HDR_CAPTURE_HDR_COLORSPACE = {
        .primaries = COLORPRIMARIES_BT2020,
        .transfunc = TRANSFUNC_SRGB,
        .matrix = MATRIX_BT2020,
        .range = RANGE_FULL,
    };
    constexpr CM_ColorSpaceInfo HDR_CAPTURE_SDR_COLORSPACE = {
        .primaries = COLORPRIMARIES_P3_D65,
        .transfunc = TRANSFUNC_SRGB,
        .matrix = MATRIX_BT601_N,
        .range = RANGE_FULL,
    };
#endif
}

class RSHdrUtil {
public:
    RSHdrUtil() = default;
    ~RSHdrUtil() = default;

    static HdrStatus CheckIsHdrSurface(const RSSurfaceRenderNode& surfaceNode);
    static HdrStatus CheckIsHdrSurfaceBuffer(const sptr<SurfaceBuffer> surfaceBuffer);
    static bool CheckIsSurfaceWithMetadata(const RSSurfaceRenderNode& surfaceNode);
    static bool CheckIsSurfaceBufferWithMetadata(const sptr<SurfaceBuffer> surfaceBuffer);
    static void UpdateSurfaceNodeLayerLinearMatrix(RSSurfaceRenderNode& surfaceNode, ScreenId screenId);
    static void UpdatePixelFormatAfterHwcCalc(RSScreenRenderNode& node);
    static void CheckPixelFormatWithSelfDrawingNode(RSSurfaceRenderNode& surfaceNode, RSScreenRenderNode& screenNode);
    static void UpdateSurfaceNodeNit(RSSurfaceRenderNode& surfaceNode, ScreenId screenId);
    static void SetHDRParam(RSScreenRenderNode& screenNode, RSSurfaceRenderNode& node, bool flag);
    static void LuminanceChangeSetDirty(RSScreenRenderNode& node);
    static bool GetRGBA1010108Enabled();
    static void CheckNotifyCallback(const sptr<RSScreenManager>& screenManager);
    static void HandleVirtualScreenHDRStatus(RSScreenRenderNode& node, const sptr<RSScreenManager>& screenManager);
    static void UpdateHDRCastProperties(RSScreenRenderNode& node, bool isNeedHDRCast, bool hdrCastColorGamut);
    static bool IsHDRCast(RSScreenRenderParams* screenParams, BufferRequestConfig& renderFrameConfig);
    static ScreenColorGamut GetScreenColorGamut(RSScreenRenderNode& node, const sptr<RSScreenManager>& screenManager);
    static bool NeedUseF16Capture(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode);
#ifdef USE_VIDEO_PROCESSING_ENGINE
    static bool HDRCastProcess(std::shared_ptr<Drawing::Image>& image, Drawing::Brush& paint,
        const Drawing::SamplingOptions& sampling, std::shared_ptr<Drawing::Surface>& surface,
        RSPaintFilterCanvas* canvas);
    static bool SetHDRCastShader(std::shared_ptr<Drawing::Image>& image, Drawing::Brush& paint,
        const Drawing::SamplingOptions& sampling);
    static GSError SetMetadata(const HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceInfo& colorspaceInfo,
        std::unique_ptr<RSRenderFrame>& renderFrame);
    static GSError SetMetadata(SurfaceBuffer* buffer,
        const HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceInfo& colorspaceInfo,
        const HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type& value);
#endif
};

} // namespace Rosen
} // namespace OHOS
#endif // RS_HDR_UTIL_H