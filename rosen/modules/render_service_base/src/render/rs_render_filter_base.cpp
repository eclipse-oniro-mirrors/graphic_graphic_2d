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

#include "effect/rs_render_filter_base.h"

#include <unordered_map>

#include "ge_visual_effect.h"
#include "ge_visual_effect_container.h"
#include "platform/common/rs_log.h"
#include "render/rs_render_color_gradient_filter.h"

namespace OHOS {
namespace Rosen {

    RSUIFilterType RSRenderFilterParaBase::GetType() const
    {
        return type_;
    }

    bool RSRenderFilterParaBase::IsValid() const
    {
        return type_ != RSUIFilterType::NONE;
    }

    void RSRenderFilterParaBase::Dump(std::string& out) const
    {
        GetDescription(out);
        out += ": [";
        std::string splitStr = "] ";
        char buffer[UINT8_MAX] = { 0 };
        for (const auto& [key, value] : properties_) {
            if (sprintf_s(buffer, UINT8_MAX, "[Type:%d Value:", static_cast<int>(key))) {
                out.append(buffer);
            }
            if (value) {
                value->Dump(out);
            } else {
                out += "nullptr";
            }
            out += splitStr;
        }
    }

    bool RSRenderFilterParaBase::WriteToParcel(Parcel& parcel)
    {
        return true;
    }

    bool RSRenderFilterParaBase::ReadFromParcel(Parcel& parcel)
    {
        return true;
    }

    std::shared_ptr<RSRenderPropertyBase> RSRenderFilterParaBase::GetRenderProperty(RSUIFilterType type) const
    {
        auto it = properties_.find(type);
        if (it != properties_.end()) {
            return it->second;
        }
        return nullptr;
    }

    std::vector<std::shared_ptr<RSRenderPropertyBase>> RSRenderFilterParaBase::GetLeafRenderProperties()
    {
        return {};
    }

    void RSRenderFilterParaBase::SetGeometry(Drawing::Canvas& canvas, float geoWidth, float geoHeight)
    {
        auto dst = canvas.GetDeviceClipBounds();
        geoWidth_ = std::ceil(geoWidth);
        geoHeight_ = std::ceil(geoHeight);
        tranX_ = dst.GetLeft();
        tranY_ = dst.GetTop();
        mat_ = canvas.GetTotalMatrix();
    }

    Drawing::CanvasInfo RSRenderFilterParaBase::GetFilterCanvasInfo() const
    {
        return Drawing::CanvasInfo { geoWidth_, geoHeight_, tranX_, tranY_, mat_ };
    }

} // namespace Rosen
} // namespace OHOS
