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

#ifndef RS_CORE_PIPELINE_UNI_RENDER_MIRROR_PROCESSOR_H
#define RS_CORE_PIPELINE_UNI_RENDER_MIRROR_PROCESSOR_H

#include "pipeline/rs_slr_scale.h"
#include "rs_uni_render_processor.h"

namespace OHOS {
namespace Rosen {
constexpr uint32_t ROI_REGIONS_MAX_CNT = 8;
struct RoiRegionInfo {
    uint32_t startX = 0;
    uint32_t startY = 0;
    uint32_t width = 0;
    uint32_t height = 0;
};

struct RoiRegions {
    uint32_t regionCnt = 0;
    RoiRegionInfo regions[ROI_REGIONS_MAX_CNT];
};

class RSUniRenderVirtualProcessor : public RSUniRenderProcessor {
public:
    static inline constexpr RSProcessorType Type = RSProcessorType::UNIRENDER_VIRTUAL_PROCESSOR;
    RSProcessorType GetType() const override
    {
        return Type;
    }

    RSUniRenderVirtualProcessor() = default;
    ~RSUniRenderVirtualProcessor() noexcept override = default;

    bool InitForRenderThread(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable, ScreenId mirroredId,
        std::shared_ptr<RSBaseRenderEngine> renderEngine) override;
    void ProcessDisplaySurfaceForRenderThread(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable) override;
    void ProcessSurface(RSSurfaceRenderNode& node) override;
    void ProcessRcdSurface(RSRcdSurfaceRenderNode& node) override;
    void PostProcess() override;
    void Fill(RSPaintFilterCanvas& canvas,
        float mainWidth, float mainHeight, float mirrorWidth, float mirrorHeight);
    void UniScale(RSPaintFilterCanvas& canvas,
        float mainWidth, float mainHeight, float mirrorWidth, float mirrorHeight);

    std::shared_ptr<RSSLRScaleFunction> GetSlrManager()
    {
        return slrManager_;
    }
    std::shared_ptr<RSPaintFilterCanvas> GetCanvas()
    {
        return canvas_;
    }
    float GetMirrorScaleX() const
    {
        return mirrorScaleX_;
    }
    float GetMirrorScaleY() const
    {
        return mirrorScaleY_;
    }
    const Drawing::Matrix& GetCanvasMatrix() const
    {
        return canvasMatrix_;
    }
    void SetDirtyInfo(std::vector<RectI>& damageRegion);
    int32_t GetBufferAge() const;
    // when virtual screen partial refresh closed, use this function to reset RoiRegion in buffer
    GSError SetRoiRegionToCodec(std::vector<RectI>& damageRegion);
    bool RequestVirtualFrame(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable);
    void CalculateTransform(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable);
    void ScaleMirrorIfNeed(const ScreenRotation angle, RSPaintFilterCanvas& canvas);
    void ProcessVirtualDisplaySurface(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable);
    void CanvasClipRegionForUniscaleMode();
    void ProcessCacheImage(Drawing::Image& cacheImage);
private:
    void CanvasInit(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable);
    GSError SetColorSpaceForMetadata(GraphicColorGamut colorSpace);
    void OriginScreenRotation(ScreenRotation screenRotation, float width, float height);
    bool EnableVisibleRect();
    bool EnableSlrScale();

    sptr<Surface> producerSurface_;
    std::unique_ptr<RSRenderFrame> renderFrame_;
    std::shared_ptr<RSPaintFilterCanvas> canvas_;
    std::map<GraphicColorGamut, HDI::Display::Graphic::Common::V1_0::colorSpaceType> COLORSPACETYPE {
        { GRAPHIC_COLOR_GAMUT_SRGB, Media::VideoProcessingEngine::CM_SRGB_LIMIT },
        { GRAPHIC_COLOR_GAMUT_DISPLAY_P3, Media::VideoProcessingEngine::CM_P3_LIMIT }
    };
    bool forceCPU_ = false;
    bool isExpand_ = false;
    float mirrorWidth_ = 0.f;
    float mirrorHeight_ = 0.f;
    float mainWidth_ = 0.f;
    float mainHeight_ = 0.f;
    float originalVirtualScreenWidth_ = 0.f; // used for recording the original virtual screen width
    float originalVirtualScreenHeight_ = 0.f; // used for recording the original virtual screen height
    float virtualScreenWidth_ = 0.f;
    float virtualScreenHeight_ = 0.f;
    float mirroredScreenWidth_ = 0.f;
    float mirroredScreenHeight_ = 0.f;
    bool updateFlag_ = false;
    bool canvasRotation_ = false;
    ScreenScaleMode scaleMode_ = ScreenScaleMode::INVALID_MODE;
    ScreenRotation screenRotation_ = ScreenRotation::ROTATION_0;
    ScreenRotation screenCorrection_ = ScreenRotation::ROTATION_0;
    float mirrorScaleX_ = 1.0f;
    float mirrorScaleY_ = 1.0f;
    Drawing::Matrix canvasMatrix_;
    Drawing::Rect visibleRect_;
    sptr<RSScreenManager> screenManager_ = nullptr;
    ScreenId virtualScreenId_ = INVALID_SCREEN_ID;
    ScreenId mirroredScreenId_ = INVALID_SCREEN_ID;
    std::shared_ptr<RSSLRScaleFunction> slrManager_ = nullptr;
};
} // namespace Rosen
} // namespace OHOS
#endif // RS_CORE_PIPELINE_UNI_RENDER_MIRROR_PROCESSOR_H
