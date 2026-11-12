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

#ifndef SAFUZZ_RANDOM_RS_NG_BLENDER_H
#define SAFUZZ_RANDOM_RS_NG_BLENDER_H

#include "effect/rs_render_blender_base.h"

namespace OHOS {
namespace Rosen {
class RandomRSNGBlenderPtr {
public:
    static std::shared_ptr<RSNGRenderBlenderBase> GetRandomValue();

private:
    static std::shared_ptr<RSNGRenderBlenderBase> GetRandomSingleBlender();
    static std::shared_ptr<RSNGRenderBlenderBase> GetRandomBlenderChain();
    static std::shared_ptr<RSNGRenderBlenderBase> GetNullValue();

#define DECLARE_BLENDER(BlenderName, BlenderType, ...) \
    static std::shared_ptr<RSNGRenderBlenderBase> GetRandom##BlenderName()

#include "effect/rs_render_blender_def.in"

#undef DECLARE_BLENDER
};

} // namespace Rosen
} // namespace OHOS
#endif // SAFUZZ_RANDOM_RS_NG_BLENDER_H
