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
#ifndef RENDER_SERVICE_BASE_CORE_RENDER_RS_FLOW_LIGHT_SWEEP_SHADER_H
#define RENDER_SERVICE_BASE_CORE_RENDER_RS_FLOW_LIGHT_SWEEP_SHADER_H

#include "render/rs_shader.h"
#include "ext/gex_flow_light_sweep_shader.h"

namespace OHOS {
namespace Rosen {

class RSB_EXPORT RSFlowLightSweepShader : public RSShader {
public:
    RSFlowLightSweepShader() = default;
    RSFlowLightSweepShader(const std::vector<std::pair<Drawing::Color, float>>& effectColors);
    RSFlowLightSweepShader(const RSFlowLightSweepShader&) = delete;
    RSFlowLightSweepShader operator=(const RSFlowLightSweepShader&) = delete;
    ~RSFlowLightSweepShader() override = default;

    void MakeDrawingShader(const RectF& rect, float progress) override;
    const std::shared_ptr<Drawing::ShaderEffect>& GetDrawingShader() const override;

    bool Marshalling(Parcel& parcel) override;
    bool Unmarshalling(Parcel& parcel) override;

private:
    std::shared_ptr<GEXFlowLightSweepParams> params_ = std::make_shared<GEXFlowLightSweepParams>();
    std::shared_ptr<GEXFlowLightSweepShader> geShader_ = nullptr;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_CORE_RENDER_RS_FLOW_LIGHT_SWEEP_SHADER_H