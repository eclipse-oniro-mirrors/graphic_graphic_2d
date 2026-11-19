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

#include "customized/random_rs_ng_blender.h"

#include "common/safuzz_log.h"
#include "customized/random_rs_render_property_base.h"
#include "random/random_data.h"
#include "random/random_engine.h"

namespace OHOS {
namespace Rosen {
namespace {
bool g_isInit = false;
std::vector<std::function<std::shared_ptr<RSNGRenderBlenderBase>()>> g_randomBlenderGenerator;
}

std::shared_ptr<RSNGRenderBlenderBase> RandomRSNGBlenderPtr::GetRandomValue()
{
    if (!g_isInit) {
        g_randomBlenderGenerator.push_back(RandomRSNGBlenderPtr::GetNullValue);
#define DECLARE_BLENDER(BlenderName, BlenderType, ...)     \
    g_randomBlenderGenerator.push_back(RandomRSNGBlenderPtr::GetRandom##BlenderName)

#include "effect/rs_render_blender_def.in"

#undef DECLARE_BLENDER
        g_isInit = true;
    }

    bool generateChain = RandomData::GetRandomBool();
    if (generateChain) {
        return RandomRSNGBlenderPtr::GetRandomBlenderChain();
    }

    return RandomRSNGBlenderPtr::GetRandomSingleBlender();
}

std::shared_ptr<RSNGRenderBlenderBase> RandomRSNGBlenderPtr::GetNullValue()
{
    return nullptr;
}

std::shared_ptr<RSNGRenderBlenderBase> RandomRSNGBlenderPtr::GetRandomSingleBlender()
{
    int index = RandomEngine::GetRandomIndex(g_randomBlenderGenerator.size() - 1);
    return g_randomBlenderGenerator[index]();
}

std::shared_ptr<RSNGRenderBlenderBase> RandomRSNGBlenderPtr::GetRandomBlenderChain()
{
    std::shared_ptr<RSNGRenderBlenderBase> head = nullptr;
    auto current = head;
    int blenderChainSize = RandomEngine::GetRandomSmallVectorLength();
    for (int i = 0; i < blenderChainSize; ++i) {
        auto blender = GetRandomSingleBlender();
        if (!blender) {
            continue;
        }

        if (!current) {
            head = blender;
        } else {
            current->nextEffect_ = blender;
        }
        current = blender;
    }

    return head;
}

#define ADD_PROPERTY_TAG(Effect, Prop) \
    value->Setter<Effect##Prop##RenderTag>( \
        RandomRSRenderPropertyBase::GetRandomValue<typename Effect##Prop##RenderTag::ValueType>())
#define DECLARE_BLENDER(BlenderName, BlenderType, ...)                                 \
std::shared_ptr<RSNGRenderBlenderBase> RandomRSNGBlenderPtr::GetRandom##BlenderName()  \
{                                                                                      \
    auto value = std::make_shared<RSNGRender##BlenderName>();                          \
    __VA_ARGS__;                                                                       \
    return value;                                                                      \
}

#include "effect/rs_render_blender_def.in"

#undef ADD_PROPERTY_TAG
#undef DECLARE_BLENDER

} // namespace Rosen
} // namespace OHOS
