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

#ifndef FRAMEWORKS_BOOTANIMATION_INCLUDE_BOOT_ANIMATION_STRATEGY_H
#define FRAMEWORKS_BOOTANIMATION_INCLUDE_BOOT_ANIMATION_STRATEGY_H

#include "boot_animation_config.h"
#include "boot_compile_progress.h"

namespace OHOS {
class BootAnimationStrategy {
public:
    BootAnimationStrategy() = default;

    virtual ~BootAnimationStrategy() = default;

    virtual void Display(int32_t duration, std::vector<BootAnimationConfig>& configs) {};

    bool CheckExitAnimation();

    bool CheckNeedOtaCompile() const;

public:
    std::shared_ptr<BootCompileProgress> bootCompileProgress_;

private:
    bool isAnimationEnd_ = false;

#ifdef FEATURE_CHECK_EXIT_ANIMATION_EXT
    bool CheckExitAnimationExt();
#endif
};
} // namespace OHOS

#endif // FRAMEWORKS_BOOTANIMATION_INCLUDE_BOOT_ANIMATION_STRATEGY_H
