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
#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_KAWASE_BLUR_SHADER_FILTER_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_KAWASE_BLUR_SHADER_FILTER_H

#include "render/rs_drawing_filter.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSKawaseBlurShaderFilter : public RSShaderFilter {
public:
    RSKawaseBlurShaderFilter(int radius);
    ~RSKawaseBlurShaderFilter() override;
    int GetRadius() const;
    std::string GetDescription() const;
    void GenerateGEVisualEffect(std::shared_ptr<Drawing::GEVisualEffectContainer> visualEffectContainer) override;
    static void SetMesablurAllEnabledByCCM(bool flag);

private:
    int radius_ = 0;
    static bool isMesablurAllEnable_;
    friend class RSMarshallingHelper;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_KAWASE_BLUR_SHADER_FILTER_H