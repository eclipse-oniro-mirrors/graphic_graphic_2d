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

#include "info_collection/rs_layer_compose_collection.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int32_t UNIFORM_RENDER_LAYER_SIZE = 1;
constexpr int32_t RCD_EXTRA_LAYER_COUNT = 2;
}
LayerComposeCollection& LayerComposeCollection::GetInstance()
{
    static LayerComposeCollection instance;
    return instance;
}

LayerComposeCollection::LayerComposeCollection()
{
}

LayerComposeCollection::~LayerComposeCollection() noexcept
{
}

void LayerComposeCollection::UpdateUniformOrOfflineComposeFrameNumberForDFX(size_t layerSize, bool hasRcdLayer)
{
    std::lock_guard<std::mutex> lock(layerMtx_);
    if (hasRcdLayer) {
        if (layerSize == static_cast<size_t>(UNIFORM_RENDER_LAYER_SIZE + RCD_EXTRA_LAYER_COUNT)) {
            ++layerComposeInfo_.uniformRenderFrameNumber;
            return;
        }
        ++layerComposeInfo_.offlineComposeFrameNumber;
        return;
    }
    if (layerSize == static_cast<size_t>(UNIFORM_RENDER_LAYER_SIZE)) {
        ++layerComposeInfo_.uniformRenderFrameNumber;
        return;
    }
    ++layerComposeInfo_.offlineComposeFrameNumber;
}

// LCOV_EXCL_START
void LayerComposeCollection::UpdateRedrawFrameNumberForDFX()
{
    std::lock_guard<std::mutex> lock(layerMtx_);
    --layerComposeInfo_.offlineComposeFrameNumber;
    ++layerComposeInfo_.redrawFrameNumber;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void LayerComposeCollection::UpdateDrawImageNumberForDFX()
{
    std::lock_guard<std::mutex> lock(layerMtx_);
    ++layerComposeInfo_.drawImageNumber;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void LayerComposeCollection::UpdateDirectCompositionFrameNumberForDFX()
{
    std::lock_guard<std::mutex> lock(layerMtx_);
    ++layerComposeInfo_.directCompositionFrameNumber;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
LayerComposeInfo LayerComposeCollection::GetLayerComposeInfo() const
{
    std::lock_guard<std::mutex> lock(layerMtx_);
    return layerComposeInfo_;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void LayerComposeCollection::ResetLayerComposeInfo()
{
    std::lock_guard<std::mutex> lock(layerMtx_);
    layerComposeInfo_ = LayerComposeInfo {};
}
// LCOV_EXCL_STOP
} // namespace Rosen
} // namespace OHOS