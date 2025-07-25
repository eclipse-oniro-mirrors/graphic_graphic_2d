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
#ifndef RENDER_RIPPLE_MASK_RENDER_PROPERTY_H
#define RENDER_RIPPLE_MASK_RENDER_PROPERTY_H

#include "common/rs_vector2.h"
#include "render/rs_render_mask.h"

namespace OHOS {
namespace Rosen {

class RSB_EXPORT RSRenderRippleMaskPara : public RSRenderMaskPara {
public:
    RSRenderRippleMaskPara(PropertyId id) :
        RSRenderMaskPara(RSUIFilterType::RIPPLE_MASK) {
        id_ = id;
    }
    virtual ~RSRenderRippleMaskPara() = default;

    static std::shared_ptr<RSRenderPropertyBase> CreateRenderProperty(RSUIFilterType type);

    template<class T>
    std::shared_ptr<RSRenderAnimatableProperty<T>> GetAnimatRenderProperty(const RSUIFilterType type)
    {
        auto property = GetRenderProperty(type);
        if (property == nullptr) {
            return nullptr;
        }
        return std::static_pointer_cast<RSRenderAnimatableProperty<T>>(property);
    }

    void GetDescription(std::string& out) const override;

    virtual bool WriteToParcel(Parcel& parcel) override;

    virtual bool ReadFromParcel(Parcel& parcel) override;

    virtual std::vector<std::shared_ptr<RSRenderPropertyBase>> GetLeafRenderProperties() override;

    std::shared_ptr<RSRenderMaskPara> LimitedDeepCopy() const override;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_RIPPLE_MASK_RENDER_PROPERTY_H
