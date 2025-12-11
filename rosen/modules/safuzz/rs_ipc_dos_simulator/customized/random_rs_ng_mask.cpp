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

#include "customized/random_rs_ng_mask.h"

#include "common/safuzz_log.h"
#include "customized/random_rs_render_property_base.h"
#include "random/random_data.h"
#include "random/random_engine.h"

namespace OHOS {
namespace Rosen {

static bool IS_INIT = false;
static std::vector<std::function<std::shared_ptr<RSNGRenderMaskBase>()>> RANDOM_MASK_GENERATOR;

std::shared_ptr<RSNGRenderMaskBase> RandomRSNGMaskPtr::GetRandomValue()
{
    if (!IS_INIT) {
        RANDOM_MASK_GENERATOR.push_back(RandomRSNGMaskPtr::GetNullValue);
        #define DECLARE_MASK(MaskName, MaskType, ...)     \
            RANDOM_MASK_GENERATOR.push_back(RandomRSNGMaskPtr::GetRandom##MaskName);

        #include "effect/rs_render_mask_def.in"

        #undef DECLARE_MASK
        IS_INIT = true;
    }

    bool generateChain = RandomData::GetRandomBool();
    if (generateChain) {
        return RandomRSNGMaskPtr::GetRandomMaskChain();
    }

    return RandomRSNGMaskPtr::GetRandomSingleMask();
}

std::shared_ptr<RSNGRenderMaskBase> RandomRSNGMaskPtr::GetNullValue()
{
    return nullptr;
}

std::shared_ptr<RSNGRenderMaskBase> RandomRSNGMaskPtr::GetRandomSingleMask()
{
    int index = RandomEngine::GetRandomIndex(RANDOM_MASK_GENERATOR.size() - 1);
    return RANDOM_MASK_GENERATOR[index]();
}

std::shared_ptr<RSNGRenderMaskBase> RandomRSNGMaskPtr::GetRandomMaskChain()
{
    std::shared_ptr<RSNGRenderMaskBase> head = nullptr;
    auto current = head;
    int maskChainSize = RandomEngine::GetRandomSmallVectorLength();
    for (int i = 0; i < maskChainSize; ++i) {
        auto mask = GetRandomSingleMask();
        if (!current) {
            head = mask; // init head
        } else {
            current->nextEffect_ = mask;
        }
        current = mask;
    }

    return head;
}

#define SEPARATOR
#define ADD_PROPERTY_TAG(Effect, Prop) \
    value->Setter<Effect##Prop##RenderTag>( \
        RandomRSRenderPropertyBase::GetRandomValue<typename Effect##Prop##RenderTag::ValueType>());
#define DECLARE_MASK(MaskName, MaskType, ...)                                       \
std::shared_ptr<RSNGRenderMaskBase> RandomRSNGMaskPtr::GetRandom##MaskName()        \
{                                                                                   \
    auto value = std::make_shared<RSNGRender##MaskName>();                          \
    __VA_ARGS__                                                                     \
    return value;                                                                   \
}

#include "effect/rs_render_mask_def.in"

#undef SEPARATOR
#undef ADD_PROPERTY_TAG
#undef DECLARE_MASK

} // namespace Rosen
} // namespace OHOS
