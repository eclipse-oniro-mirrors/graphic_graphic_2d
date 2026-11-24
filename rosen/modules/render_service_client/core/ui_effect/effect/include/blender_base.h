/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef UIEFFECT_EFFECT_BLENDER_BASE_H
#define UIEFFECT_EFFECT_BLENDER_BASE_H

#include <memory>

#include "blender.h"

namespace OHOS {
namespace Rosen {

class BlenderBase : public Blender {
public:
    BlenderBase()
    {
        blenderType_ = Blender::BLENDER_BASE;
    }
    ~BlenderBase() override = default;

    void SetBlender(const std::shared_ptr<Blender>& blender)
    {
        oriBlender_ = blender;
    }

    const Blender* GetBlender() const
    {
        return oriBlender_.get();
    }

private:
    std::shared_ptr<Blender> oriBlender_;
};
} // namespace Rosen
} // namespace OHOS
#endif // UIEFFECT_EFFECT_BLENDER_BASE_H
