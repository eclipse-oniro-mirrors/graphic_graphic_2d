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

#include "customized/random_rs_ng_shape.h"

#include "common/safuzz_log.h"
#include "customized/random_rs_render_property_base.h"
#include "random/random_data.h"
#include "random/random_engine.h"

namespace OHOS {
namespace Rosen {

constexpr uint32_t MAX_SHAPE_DEPTH = 5; // 5: MAX_SHAPE_DEPTH
static uint32_t SHAPE_DEPTH = 0;
static bool IS_INIT = false;
static std::vector<std::function<std::shared_ptr<RSNGRenderShapeBase>()>> RANDOM_SHAPE_GENERATOR;

void RandomRSNGShapePtr::ResetShapeDepth()
{
    SHAPE_DEPTH = 0;
}

std::shared_ptr<RSNGRenderShapeBase> RandomRSNGShapePtr::GetRandomValue()
{
    if (!IS_INIT) {
        RANDOM_SHAPE_GENERATOR.push_back(RandomRSNGShapePtr::GetNullValue);
        #define DECLARE_SHAPE(ShapeName, ShapeType, ...)     \
            RANDOM_SHAPE_GENERATOR.push_back(RandomRSNGShapePtr::GetRandom##ShapeName);

        #include "effect/rs_render_shape_def.in"

        #undef DECLARE_SHAPE
        IS_INIT = true;
    }

    bool generateChain = RandomData::GetRandomBool();
    if (generateChain) {
        return RandomRSNGShapePtr::GetRandomShapeChain();
    }

    return RandomRSNGShapePtr::GetRandomSingleShape();
}

std::shared_ptr<RSNGRenderShapeBase> RandomRSNGShapePtr::GetNullValue()
{
    return nullptr;
}

std::shared_ptr<RSNGRenderShapeBase> RandomRSNGShapePtr::GetRandomSingleShape()
{
    if (SHAPE_DEPTH > MAX_SHAPE_DEPTH) {
        return nullptr;
    }
    SHAPE_DEPTH++;
    auto index = RandomEngine::GetRandomIndex(RANDOM_SHAPE_GENERATOR.size() - 1);
    return RANDOM_SHAPE_GENERATOR[index]();
}

std::shared_ptr<RSNGRenderShapeBase> RandomRSNGShapePtr::GetRandomShapeChain()
{
    std::shared_ptr<RSNGRenderShapeBase> head = nullptr;
    auto current = head;
    int shapeChainSize = RandomEngine::GetRandomSmallVectorLength();
    for (int i = 0; i < shapeChainSize; ++i) {
        auto shape = GetRandomSingleShape();
        if (!current) {
            head = shape; // init head
        } else {
            current->nextEffect_ = shape;
        }
        current = shape;
    }

    return head;
}

#define SEPARATOR
#define ADD_PROPERTY_TAG(Effect, Prop) \
    value->Setter<Effect##Prop##RenderTag>( \
        RandomRSRenderPropertyBase::GetRandomValue<typename Effect##Prop##RenderTag::ValueType>());
#define DECLARE_SHAPE(ShapeName, ShapeType, ...)                                    \
std::shared_ptr<RSNGRenderShapeBase> RandomRSNGShapePtr::GetRandom##ShapeName()     \
{                                                                                   \
    auto value = std::make_shared<RSNGRender##ShapeName>();                         \
    __VA_ARGS__                                                                     \
    return value;                                                                   \
}

#include "effect/rs_render_shape_def.in"

#undef SEPARATOR
#undef ADD_PROPERTY_TAG
#undef DECLARE_SHAPE

} // namespace Rosen
} // namespace OHOS
