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

#include "params/rs_effect_render_params.h"
#include "platform/common/rs_log.h"

namespace OHOS::Rosen {
RSEffectRenderParams::RSEffectRenderParams(NodeId id) : RSRenderParams(id) {}

void RSEffectRenderParams::OnSync(const std::unique_ptr<RSRenderParams>& target)
{
    auto targetEffectRenderParam = static_cast<RSEffectRenderParams*>(target.get());
    if (targetEffectRenderParam == nullptr) {
        RS_LOGE("targetCanvasDrawingParam::OnSync targetCanvasDrawingParam is null");
        return;
    }
    targetEffectRenderParam->cacheValid_ = cacheValid_;
    targetEffectRenderParam->hasEffectChildren_ = hasEffectChildren_;
    targetEffectRenderParam->isDarkColorMode_ = isDarkColorMode_;
    targetEffectRenderParam->isIntersectWithDRM_ = isIntersectWithDRM_;

    RSRenderParams::OnSync(target);
}
void RSEffectRenderParams::SetCacheValid(bool valid)
{
    if (cacheValid_ == valid) {
        return;
    }
    cacheValid_ = valid;
    needSync_ = true;
}

bool RSEffectRenderParams::GetCacheValid() const
{
    return cacheValid_;
}

void RSEffectRenderParams::SetHasEffectChildren(bool hasEffectChildren)
{
    if (hasEffectChildren_ == hasEffectChildren) {
        return;
    }
    hasEffectChildren_ = hasEffectChildren;
    needSync_ = true;
}

bool RSEffectRenderParams::GetHasEffectChildren() const
{
    return hasEffectChildren_;
}

void RSEffectRenderParams::SetEffectIntersectWithDRM(bool intersect)
{
    if (isIntersectWithDRM_ == intersect) {
        return;
    }
    isIntersectWithDRM_ = intersect;
    needSync_ = true;
}

bool RSEffectRenderParams::GetEffectIntersectWithDRM() const
{
    return isIntersectWithDRM_;
}

void RSEffectRenderParams::SetDarkColorMode(bool isDark)
{
    if (isDarkColorMode_ == isDark) {
        return;
    }
    isDarkColorMode_ = isDark;
    needSync_ = true;
}

bool RSEffectRenderParams::GetDarkColorMode() const
{
    return isDarkColorMode_;
}
} // namespace OHOS::Rosen
