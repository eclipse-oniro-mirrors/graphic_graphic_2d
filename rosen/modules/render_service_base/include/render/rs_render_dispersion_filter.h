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
#ifndef RENDER_DISPERSION_FILTER_RENDER_PROPERTY_H
#define RENDER_DISPERSION_FILTER_RENDER_PROPERTY_H

#include <vector>

#include "common/rs_vector2.h"

#include "render/rs_render_filter_base.h"

namespace OHOS {
namespace Rosen {
class RSShaderMask;

class RSB_EXPORT RSRenderDispersionFilterPara : public RSRenderFilterParaBase {
public:
    RSRenderDispersionFilterPara(PropertyId id, RSUIFilterType maskType = RSUIFilterType::NONE) :
        RSRenderFilterParaBase(RSUIFilterType::DISPERSION), maskType_(maskType) 
    {
        id_ = id;
    }

    virtual ~RSRenderDispersionFilterPara() = default;

    std::shared_ptr<RSRenderFilterParaBase> DeepCopy() const override;

    void GetDescription(std::string& out) const override;

    bool WriteToParcel(Parcel& parcel) override;

    bool ReadFromParcel(Parcel& parcel) override;

    std::vector<std::shared_ptr<RSRenderPropertyBase>> GetLeafRenderProperties() override;

    std::shared_ptr<RSRenderMaskPara> GetRenderMask();

    RSUIFilterType GetMaskType() const
    {
        return maskType_;
    }
    bool ParseFilterValues() override;
    void GenerateGEVisualEffect(
        std::shared_ptr<Rosen::Drawing::GEVisualEffectContainer> visualEffectContainer) override;

    const std::shared_ptr<Rosen::RSShaderMask>& GetMask() const;

private:
    static std::shared_ptr<RSRenderPropertyBase> CreateRenderProperty(RSUIFilterType type);
    void CalculateHash();

    std::shared_ptr<RSShaderMask> mask_;
    float opacity_;
    Vector2f redOffset_;
    Vector2f greenOffset_;
    Vector2f blueOffset_;
    RSUIFilterType maskType_ = RSUIFilterType::NONE;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_DISPERSION_FILTER_RENDER_PROPERTY_H