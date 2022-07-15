/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef RS_CORE_PIPELINE_RS_COMPOSER_ADAPTER_H
#define RS_CORE_PIPELINE_RS_COMPOSER_ADAPTER_H

#include "hdi_backend.h"

#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "screen_manager/rs_screen_manager.h"

namespace OHOS {
namespace Rosen {
struct ComposeInfo {
    IRect srcRect;
    IRect dstRect;
    IRect visibleRect;
    int32_t zOrder { 0 };
    LayerAlpha alpha;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> fence = SyncFence::INVALID_FENCE;
    BlendType blendType;
    bool needClient;
};

using FallbackCallback = std::function<void(const sptr<Surface>& surface, const std::vector<LayerInfoPtr>& layers)>;

class RSComposerAdapter {
public:
    RSComposerAdapter() = default;
    ~RSComposerAdapter() noexcept = default;

    // noncopyable
    RSComposerAdapter(const RSComposerAdapter&) = delete;
    void operator=(const RSComposerAdapter&) = delete;

    bool Init(ScreenId screenId, int32_t offsetX, int32_t offsetY, float mirrorAdaptiveCoefficient,
        const FallbackCallback& cb);

    LayerInfoPtr CreateLayer(RSSurfaceRenderNode& node);
    LayerInfoPtr CreateLayer(RSDisplayRenderNode& node);
    void CommitLayers(const std::vector<LayerInfoPtr>& layers);

private:
    // check if the node is out of the screen region.
    bool IsOutOfScreenRegion(RSSurfaceRenderNode& node) const;
    ComposeInfo BuildComposeInfo(RSSurfaceRenderNode& node) const;
    ComposeInfo BuildComposeInfo(RSDisplayRenderNode& node) const;
    void SetComposeInfoToLayer(
        const LayerInfoPtr& layer,
        const ComposeInfo& info,
        const sptr<Surface>& surface,
        RSBaseRenderNode* node) const;
    void DealWithNodeGravity(RSSurfaceRenderNode& node, ComposeInfo& info) const;

    void LayerRotate(const LayerInfoPtr& layer) const;
    void LayerCrop(const LayerInfoPtr& layer) const;
    void LayerScaleDown(const LayerInfoPtr& layer) const;

    void OnPrepareComplete(sptr<Surface>& surface, const PrepareCompleteParam& param, void* data);
    HdiBackend *hdiBackend_ = nullptr;
    std::shared_ptr<HdiOutput> output_;
    ScreenInfo screenInfo_;

    // The offset on dst screen for all layers.
    int32_t offsetX_ = 0;
    int32_t offsetY_ = 0;

    float mirrorAdaptiveCoefficient_ = 1.0f;
    FallbackCallback fallbackCb_;
};
} // namespace Rosen
} // namespace OHOS
#endif // RS_CORE_PIPELINE_RS_COMPOSER_ADAPTER_H
