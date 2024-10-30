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
#ifndef UIEFFECT_FILTER_PIXEL_STRETCH_PARA_H
#define UIEFFECT_FILTER_PIXEL_STRETCH_PARA_H

#include "common/rs_vector4.h"
#include "effect/shader_effect.h"
#include "filter_para.h"
#include "ui_effect/utils.h"

namespace OHOS {
namespace Rosen {
constexpr std::pair<float, float> STRETCH_PERCENT_LIMITS {-1.f, 1.f}; // limits for stretch percent

class PixelStretchPara : public FilterPara {
public:
    PixelStretchPara()
    {
        this->type_ = FilterPara::ParaType::PIXEL_STRETCH;
    }
    ~PixelStretchPara() override = default;

    inline void SetStretchPercent(const Vector4f& stretchPercent)
    {
        if (UIEffect::IsParaSameSign(stretchPercent)) {
            stretchPercent_ = UIEffect::GetLimitedPara(stretchPercent, STRETCH_PERCENT_LIMITS);
        }
    }

    const Vector4f& GetStretchPercent() const
    {
        return stretchPercent_;
    }

    void SetTileMode(Drawing::TileMode stretchTileMode)
    {
        stretchTileMode_ = stretchTileMode;
    }

    Drawing::TileMode GetTileMode() const
    {
        return stretchTileMode_;
    }

private:
    Vector4f stretchPercent_;
    Drawing::TileMode stretchTileMode_ = Drawing::TileMode::CLAMP;
};
} // namespace Rosen
} // namespace OHOS
#endif // UIEFFECT_FILTER_PIXEL_STRETCH_PARA_H
