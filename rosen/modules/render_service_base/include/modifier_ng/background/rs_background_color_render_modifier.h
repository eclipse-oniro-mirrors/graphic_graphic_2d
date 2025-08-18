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

#ifndef RENDER_SERVICE_BASE_MODIFIER_NG_BACKGROUND_RS_BACKGROUND_COLOR_RENDER_MODIFIER_H
#define RENDER_SERVICE_BASE_MODIFIER_NG_BACKGROUND_RS_BACKGROUND_COLOR_RENDER_MODIFIER_H

#include "modifier_ng/rs_render_modifier_ng.h"

namespace OHOS::Rosen::ModifierNG {
class RSB_EXPORT RSBackgroundColorRenderModifier : public RSDisplayListRenderModifier {
public:
    RSBackgroundColorRenderModifier() = default;
    ~RSBackgroundColorRenderModifier() override = default;

    static inline constexpr auto Type = RSModifierType::BACKGROUND_COLOR;
    // LCOV_EXCL_START
    RSModifierType GetType() const override
    {
        return Type;
    }
    // LCOV_EXCL_STOP

    static void ResetProperties(RSProperties& properties);

private:
    static const LegacyPropertyApplierMap LegacyPropertyApplierMap_;
    // LCOV_EXCL_START
    const LegacyPropertyApplierMap& GetLegacyPropertyApplierMap() const override
    {
        return LegacyPropertyApplierMap_;
    }
    // LCOV_EXCL_STOP
};
} // namespace OHOS::Rosen::ModifierNG
#endif // RENDER_SERVICE_BASE_MODIFIER_NG_BACKGROUND_RS_BACKGROUND_COLOR_RENDER_MODIFIER_H
