/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>

#include "rs_hwc_region_dfx.h"

#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_render_thread_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "system/rs_system_parameters.h"

namespace OHOS::Rosen {
namespace {
constexpr float HWC_DFX_FILL_ALPHA = 0.3f;
}

void RSHwcRegionDfx::Draw(RSPaintFilterCanvas& canvas)
{
    if (!RSSystemProperties::GetHwcRegionDfxEnabled()) {
        return;
    }
#ifdef RS_ENABLE_GPU
    auto& hardwareDrawables =
        RSUniRenderThread::Instance().GetRSRenderThreadParams()->GetHardwareEnabledTypeDrawables();
    static uint32_t updateCnt = 0;
    if (++updateCnt == UINT32_MAX) {
        updateCnt = 0;
    }
    for (const auto& [_, __, drawable] : hardwareDrawables) {
        if (UNLIKELY(!drawable || !drawable->GetRenderParams())) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
        std::string extraInfo = surfaceParams->GetName() + " UpdateCnt: " + std::to_string(updateCnt);
        if (surfaceParams->GetHardwareEnabled()) {
            RSUniRenderUtil::DrawRectForDfx(canvas, surfaceParams->GetDstRect(), Drawing::Color::COLOR_BLUE,
                HWC_DFX_FILL_ALPHA, extraInfo);
        } else {
            RSUniRenderUtil::DrawRectForDfx(canvas, surfaceParams->GetDstRect(), Drawing::Color::COLOR_RED,
                HWC_DFX_FILL_ALPHA, extraInfo);
        }
    }
#endif
}
} // namespace OHOS::Rosen
