
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "modifier/rs_modifier_manager.h"

#include "modifier/rs_property_modifier.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSModifierManager::RSModifierManager()
{
    animationManager_ = std::make_shared<RSUIAnimationManager>();
}

void RSModifierManager::AddModifier(const std::shared_ptr<RSModifier>& modifier)
{
    modifiers_.insert(modifier);
}

void RSModifierManager::Draw()
{
    if (modifiers_.empty()) {
        return;
    }

    for (auto modifier : modifiers_) {
        modifier->UpdateToRender();
    }
    modifiers_.clear();
}

std::shared_ptr<RSUIAnimationManager>& RSModifierManager::GetAnimationManager()
{
    if (animationManager_ == nullptr) {
        animationManager_ = std::make_shared<RSUIAnimationManager>();
    }
    return animationManager_;
}
} // namespace Rosen
} // namespace OHOS
