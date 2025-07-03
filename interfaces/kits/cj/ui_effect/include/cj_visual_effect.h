/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CJ_VISUAL_EFFECT_H
#define CJ_VISUAL_EFFECT_H

#include <iostream>
#include <cstdint>
#include <vector>
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "cj_ui_effect_log.h"
#include "effect/include/background_color_effect_para.h"
#include "effect/include/blender.h"
#include "effect/include/brightness_blender.h"
#include "effect/include/visual_effect.h"
#include "effect/include/visual_effect_para.h"

namespace OHOS {
namespace Rosen {
class CJVisualEffect : public OHOS::FFI::FFIData {
    DECL_TYPE(CJVisualEffect, OHOS::FFI::FFIData)
public:
    explicit CJVisualEffect(int32_t *errCode);
    virtual ~CJVisualEffect() override = default;
private:
    std::shared_ptr<VisualEffect> m_EffectObj = nullptr;
};
}
}

#endif