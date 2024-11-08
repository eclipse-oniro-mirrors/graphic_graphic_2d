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

#include "rs_processor.h"

#include <memory>

#include "rs_base_render_util.h"
#include "rs_main_thread.h"

#include "common/rs_obj_abs_geometry.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "pipeline/rs_display_render_node.h"
#include "platform/common/rs_log.h"
#include "pipeline/rs_uni_render_util.h"
#ifdef SOC_PERF_ENABLE
#include "socperf_client.h"
#endif
#ifdef FRAME_AWARE_TRACE
#include "render_frame_trace.h"

using namespace FRAME_TRACE;
#endif

namespace OHOS {
namespace Rosen {
namespace {
constexpr uint32_t PERF_LEVEL_0 = 0;
constexpr uint32_t PERF_LEVEL_1 = 1;
constexpr uint32_t PERF_LEVEL_2 = 2;
constexpr int32_t PERF_LEVEL_1_REQUESTED_CODE = 10013;
constexpr int32_t PERF_LEVEL_2_REQUESTED_CODE = 10014;
constexpr int32_t PERF_LEVEL_3_REQUESTED_CODE = 10015;
constexpr int64_t PERF_TIME_OUT = 950;
constexpr uint32_t PERF_LEVEL_INTERVAL = 10;
constexpr uint32_t PERF_LAYER_START_NUM = 12;
#ifdef FRAME_AWARE_TRACE
constexpr uint32_t FRAME_TRACE_LAYER_NUM_1 = 11;
constexpr uint32_t FRAME_TRACE_LAYER_NUM_2 = 13;
constexpr int32_t FRAME_TRACE_PERF_REQUESTED_CODE = 10024;
#endif

void PerfRequest(int32_t perfRequestCode, bool onOffTag)
{
#ifdef SOC_PERF_ENABLE
    OHOS::SOCPERF::SocPerfClient::GetInstance().PerfRequestEx(perfRequestCode, onOffTag, "");
    RS_LOGD("RSProcessor::soc perf info [%{public}d %{public}d]", perfRequestCode, onOffTag);
#endif
}
}

void RSProcessor::RequestPerf(uint32_t layerLevel, bool onOffTag)
{
    RSUniRenderUtil::RequestPerf(layerLevel, onOffTag);
}

bool RSProcessor::InitForRenderThread(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable, ScreenId mirroredId,
    std::shared_ptr<RSBaseRenderEngine> renderEngine)
{
    if (renderEngine == nullptr) {
        RS_LOGE("renderEngine is nullptr");
        return false;
    }
    auto& params = displayDrawable.GetRenderParams();
    if (params == nullptr) {
        RS_LOGE("RSProcessor::InitForRenderThread params is null!");
        return false;
    }
    auto displayParams = static_cast<RSDisplayRenderParams*>(params.get());
    offsetX_ = displayParams->GetDisplayOffsetX();
    offsetY_ = displayParams->GetDisplayOffsetY();
    mirroredId_ = mirroredId;
    renderEngine_ = renderEngine;
    screenInfo_ = displayParams->GetScreenInfo();
    screenInfo_.rotation = displayParams->GetNodeRotation();

    // CalculateScreenTransformMatrix
    auto mirroredNodeDrawable = displayParams->GetMirrorSourceDrawable().lock();
    if (!mirroredNodeDrawable) {
        screenTransformMatrix_ = displayParams->GetMatrix();
    } else if (mirroredNodeDrawable->GetRenderParams()) {
        auto& mirrorNodeParam = mirroredNodeDrawable->GetRenderParams();
        screenTransformMatrix_ = mirrorNodeParam->GetMatrix();
        if (mirroredId_ != INVALID_SCREEN_ID) {
            auto mirroredScreenInfo = mirrorNodeParam->GetScreenInfo();
            CalculateMirrorAdaptiveCoefficient(
                static_cast<float>(screenInfo_.width), static_cast<float>(screenInfo_.height),
                static_cast<float>(mirroredScreenInfo.width), static_cast<float>(mirroredScreenInfo.height)
            );
        }
    }

    // set default render frame config
    renderFrameConfig_ = RSBaseRenderUtil::GetFrameBufferRequestConfig(screenInfo_);
    return true;
}

bool RSProcessor::Init(RSDisplayRenderNode& node, int32_t offsetX, int32_t offsetY, ScreenId mirroredId,
    std::shared_ptr<RSBaseRenderEngine> renderEngine)
{
    if (renderEngine == nullptr) {
        RS_LOGE("renderEngine is nullptr");
        return false;
    }
    auto screenManager = CreateOrGetScreenManager();
    if (screenManager == nullptr) {
        RS_LOGE("RSPhysicalScreenProcessor::Init: ScreenManager is nullptr");
        return false;
    }
    renderEngine_ = renderEngine;
    offsetX_ = offsetX;
    offsetY_ = offsetY;
    mirroredId_ = mirroredId;
    screenInfo_ = screenManager->QueryScreenInfo(node.GetScreenId());
    screenInfo_.rotation = node.GetRotation();
    auto mirrorNode = node.GetMirrorSource().lock();
    CalculateScreenTransformMatrix(mirrorNode ? *mirrorNode : node);

    if (mirroredId_ != INVALID_SCREEN_ID) {
        mirroredScreenInfo_ = screenManager->QueryScreenInfo(mirroredId_);
        mirroredScreenInfo_.rotation = mirrorNode->GetRotation();
        CalculateMirrorAdaptiveMatrix();
    }

    // set default render frame config
    renderFrameConfig_ = RSBaseRenderUtil::GetFrameBufferRequestConfig(screenInfo_);
    return true;
}

void RSProcessor::SetMirrorScreenSwap(const RSDisplayRenderNode& node)
{
    auto mirroredNode = node.GetMirrorSource().lock();
    if (mirroredNode == nullptr) {
        RS_LOGE("RSProcessor::Init: Get mirroredNode failed");
        return;
    }
    if (mirroredNode->GetRotation() == ScreenRotation::ROTATION_90 ||
        mirroredNode->GetRotation() == ScreenRotation::ROTATION_270) {
        std::swap(screenInfo_.width, screenInfo_.height);
        std::swap(renderFrameConfig_.width, renderFrameConfig_.height);
    }
}

void RSProcessor::CalculateScreenTransformMatrix(const RSDisplayRenderNode& node)
{
    auto& boundsGeoPtr = (node.GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr != nullptr) {
        boundsGeoPtr->UpdateByMatrixFromSelf();
        screenTransformMatrix_ = boundsGeoPtr->GetMatrix();
    }
}

void RSProcessor::CalculateMirrorAdaptiveCoefficient(float curWidth, float curHeight,
    float mirroredWidth, float mirroredHeight)
{
    if (std::fabs(mirroredWidth) < 1e-6 || std::fabs(mirroredHeight) < 1e-6) {
        RS_LOGE("RSSoftwareProcessor::Init mirroredScreen width or height is zero");
        return;
    }
    mirrorAdaptiveCoefficient_ = std::min(curWidth / mirroredWidth, curHeight / mirroredHeight);
}

void RSProcessor::SetSecurityDisplay(bool isSecurityDisplay)
{
    isSecurityDisplay_ = isSecurityDisplay;
}

void RSProcessor::SetDisplayHasSecSurface(bool displayHasSecSurface)
{
    displayHasSecSurface_ = displayHasSecSurface;
}

void RSProcessor::CalculateMirrorAdaptiveMatrix()
{
    CalculateMirrorAdaptiveCoefficient(static_cast<float>(screenInfo_.GetRotatedWidth()),
        static_cast<float>(screenInfo_.GetRotatedHeight()), static_cast<float>(mirroredScreenInfo_.GetRotatedWidth()),
        static_cast<float>(mirroredScreenInfo_.GetRotatedHeight()));

    float rotation = 0.0f;
    float offsetX = 0.0f;
    float offsetY = 0.0f;

    switch (screenInfo_.rotation) {
        case ScreenRotation::ROTATION_90:
            rotation = -90.0f;
            offsetX = screenInfo_.GetRotatedWidth() * -1.0f;
            break;
        case ScreenRotation::ROTATION_180:
            rotation = -180.0f;
            offsetX = screenInfo_.GetRotatedWidth() * -1.0f;
            offsetY = screenInfo_.GetRotatedHeight() * -1.0f;
            break;
        case ScreenRotation::ROTATION_270:
            rotation = -270.0f;
            offsetY = screenInfo_.GetRotatedHeight() * -1.0f;
            break;
        default:
            break;
    }

    // align center
    offsetX +=
        (screenInfo_.GetRotatedWidth() - mirroredScreenInfo_.GetRotatedWidth() * mirrorAdaptiveCoefficient_) / 2.0f;
    offsetY +=
        (screenInfo_.GetRotatedHeight() - mirroredScreenInfo_.GetRotatedHeight() * mirrorAdaptiveCoefficient_) /
        2.0f;

    mirrorAdaptiveMatrix_.PreRotate(rotation);
    mirrorAdaptiveMatrix_.PreTranslate(offsetX, offsetY);
    mirrorAdaptiveMatrix_.PreScale(mirrorAdaptiveCoefficient_, mirrorAdaptiveCoefficient_);
}

} // namespace Rosen
} // namespace OHOS
