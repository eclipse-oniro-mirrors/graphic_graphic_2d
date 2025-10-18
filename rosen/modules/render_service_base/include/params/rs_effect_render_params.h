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

#ifndef RENDER_SERVICE_BASE_PARAMS_RS_EFFECT_RENDER_PARAMS_H
#define RENDER_SERVICE_BASE_PARAMS_RS_EFFECT_RENDER_PARAMS_H

#include "params/rs_render_params.h"

namespace OHOS::Rosen {
class RSB_EXPORT RSEffectRenderParams : public RSRenderParams {
public:
    explicit RSEffectRenderParams(NodeId id);
    ~RSEffectRenderParams() override = default;
    void OnSync(const std::unique_ptr<RSRenderParams>& target) override;

    void SetCacheValid(bool valid);
    bool GetCacheValid() const;

    void SetHasEffectChildren(bool hasEffectChildren);
    bool GetHasEffectChildren() const;

    void SetHasHarmoniumChildren(bool hasHarmoniumChildren);
    bool GetHasHarmoniumChildren() const;

    void SetEffectIntersectWithDRM(bool intersect);
    bool GetEffectIntersectWithDRM() const;
    void SetDarkColorMode(bool isDark);
    bool GetDarkColorMode() const;

private:
    bool cacheValid_ = false;
    bool hasEffectChildren_ = false;
    bool hasHarmoniumChildren_ = false;
    bool isIntersectWithDRM_ = false;
    bool isDarkColorMode_ = false;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PARAMS_RS_EFFECT_RENDER_PARAMS_H
