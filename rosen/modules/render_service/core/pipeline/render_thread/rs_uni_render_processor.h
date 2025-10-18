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

#ifndef RS_CORE_PIPELINE_UNI_RENDER_PROCESSOR_H
#define RS_CORE_PIPELINE_UNI_RENDER_PROCESSOR_H

#include "pipeline/rs_processor.h"
#include "rs_composer_adapter.h"
#include "rs_uni_render_composer_adapter.h"

namespace OHOS {
namespace Rosen {
class RSUniRenderProcessor : public RSProcessor {
public:
    static inline constexpr RSProcessorType Type = RSProcessorType::UNIRENDER_PROCESSOR;
    RSProcessorType GetType() const override
    {
        return Type;
    }

    RSUniRenderProcessor();
    ~RSUniRenderProcessor() noexcept override;

    bool Init(RSScreenRenderNode& node, int32_t offsetX, int32_t offsetY, ScreenId mirroredId,
              std::shared_ptr<RSBaseRenderEngine> renderEngine) override;
    void CreateLayer(const RSSurfaceRenderNode& node, RSSurfaceRenderParams& params,
        const std::shared_ptr<ProcessOfflineResult>& offlineResult = nullptr) override;
    void ProcessSurface(RSSurfaceRenderNode& node) override;
    void ProcessScreenSurface(RSScreenRenderNode& node) override;
    void ProcessRcdSurface(RSRcdSurfaceRenderNode& node) override;
    void PostProcess() override;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    std::vector<LayerInfoPtr> GetLayers() const;
#endif

    // called by render thread
    bool InitForRenderThread(DrawableV2::RSScreenRenderNodeDrawable& screenDrawable,
        std::shared_ptr<RSBaseRenderEngine> renderEngine) override;
    bool UpdateMirrorInfo(DrawableV2::RSLogicalDisplayRenderNodeDrawable& displayDrawable) override;
    void CreateLayerForRenderThread(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable,
        const std::shared_ptr<ProcessOfflineResult>& offlineResult = nullptr) override;
    void ProcessScreenSurfaceForRenderThread(DrawableV2::RSScreenRenderNodeDrawable& screenDrawable) override;
    // hpae offline
    bool ProcessOfflineLayer(
        std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>& surfaceDrawable, bool async) override;
    bool ProcessOfflineLayer(std::shared_ptr<RSSurfaceRenderNode>& node) override;

private:
    bool GetForceClientForDRM(RSSurfaceRenderParams& params);
    LayerInfoPtr GetLayerInfo(RSSurfaceRenderParams& params, sptr<SurfaceBuffer>& buffer,
        sptr<SurfaceBuffer>& prebuffer, const sptr<IConsumerSurface>& consumer, const sptr<SyncFence>& acquireFence,
        const std::shared_ptr<ProcessOfflineResult>& offlineResult = nullptr);
    void CreateSolidColorLayer(LayerInfoPtr layer, RSSurfaceRenderParams& params);
    void HandleTunnelLayerParameters(RSSurfaceRenderParams& params, LayerInfoPtr& layer);
    void ScaleLayerIfNeeded(RSLayerInfo& layerInfo);
    std::unique_ptr<RSUniRenderComposerAdapter> uniComposerAdapter_;
    std::vector<LayerInfoPtr> layers_;
};
} // namespace Rosen
} // namespace OHOS
#endif // RS_CORE_PIPELINE_UNI_RENDER_PROCESSOR_H
