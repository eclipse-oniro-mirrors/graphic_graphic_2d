/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef SKIA_HM_SYMBOL_CONFIG_OHOS_H
#define SKIA_HM_SYMBOL_CONFIG_OHOS_H

#include "include/core/HMSymbol.h"

#include "text/hm_symbol.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

class SkiaHmSymbolConfigOhos {
public:
    static DrawingSymbolLayersGroups GetSymbolLayersGroups(uint16_t glyphId);

    static std::vector<std::vector<DrawingPiecewiseParameter>> GetGroupParameters(
        DrawingAnimationType type, uint16_t groupSum, uint16_t animationMode = 0,
        DrawingCommonSubType commonSubType = DrawingCommonSubType::DOWN);
private:
    static DrawingAnimationSetting ConvertToDrawingAnimationSetting(AnimationSetting setting);

    static DrawingRenderGroup ConvertToDrawingRenderGroup(RenderGroup group);

    static std::vector<DrawingGroupInfo> ConvertToDrawingGroupInfo(std::vector<GroupInfo> infos);
};

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS

#endif