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
#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_MAGNIFIER_PARA_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_MAGNIFIER_PARA_H

#include "common/rs_macros.h"
#include <cstdint>
namespace OHOS {
namespace Rosen {

class RSB_EXPORT RSMagnifierParams {
public:
    float factor_ = 0.f;
    float width_ = 0.f;
    float height_ = 0.f;
    float cornerRadius_ = 0.f;
    float borderWidth_ = 0.f;
    float offsetX_ = 0.f;
    float offsetY_ = 0.f;

    float shadowOffsetX_ = 0.f;
    float shadowOffsetY_ = 0.f;
    float shadowSize_ = 0.f;
    float shadowStrength_ = 0.f;

    // rgba
    uint32_t gradientMaskColor1_ = 0x00000000;
    uint32_t gradientMaskColor2_ = 0x00000000;
    uint32_t outerContourColor1_ = 0x00000000;
    uint32_t outerContourColor2_ = 0x00000000;

    explicit RSMagnifierParams() {}

    ~RSMagnifierParams() = default;
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_MAGNIFIER_PARA_H
