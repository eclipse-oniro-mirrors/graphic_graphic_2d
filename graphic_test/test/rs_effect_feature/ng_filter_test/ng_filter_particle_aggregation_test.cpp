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

#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"
#include "ng_filter_test_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
const int SCREEN_WIDTH = 1200;
const int SCREEN_HEIGHT = 2000;
}

class NGFilterParticleAggregationTest : public RSGraphicTest {
public:
    void BeforeEach() override
    {
        SetScreenSize(SCREEN_WIDTH, SCREEN_HEIGHT);
    }
};

GRAPHIC_TEST(NGFilterParticleAggregationTest, EFFECT_TEST, Set_NG_Filter_Particle_Aggregation_Test)
{
    auto particleAggregationPtr = CreateFilter(RSNGEffectType::PARTICLE_AGGREGATION);
    auto particleAggregationFilter =
        std::static_pointer_cast<RSNGParticleAggregationFilter>(particleAggregationPtr);
    particleAggregationFilter->Setter<ParticleAggregationProgressTag>(0.5f);
    particleAggregationFilter->Setter<ParticleAggregationDirectionTag>(0.0f);
    particleAggregationFilter->Setter<ParticleAggregationMaxParticleCountTag>(10000.0f);

    int nodeWidth = 200;
    int nodeHeight = 200;
    int start = 50;
    int row = 4;

    for (int i = 0; i < row; i++) {
        auto backgroundNode = SetUpNodeBgImage(BG_PATH,
            {start, start + (start + nodeWidth) * i, nodeWidth * (i + 1), nodeHeight * (i + 1)});
        backgroundNode->SetForegroundNGFilter(particleAggregationFilter);
        GetRootNode()->AddChild(backgroundNode);
        RegisterNode(backgroundNode);
    }
}

GRAPHIC_TEST(NGFilterParticleAggregationTest, EFFECT_TEST, Set_NG_Filter_Particle_Aggregation_Progress_Test)
{
    int nodeWidth = 200;
    int nodeHeight = 200;
    int start = 50;
    int row = 4;
    std::vector<float> progressValues = {0.0f, 0.25f, 0.5f, 0.75f};

    for (int i = 0; i < row; i++) {
        auto particleAggregationPtr = CreateFilter(RSNGEffectType::PARTICLE_AGGREGATION);
        auto particleAggregationFilter =
            std::static_pointer_cast<RSNGParticleAggregationFilter>(particleAggregationPtr);
        particleAggregationFilter->Setter<ParticleAggregationProgressTag>(progressValues[i]);
        particleAggregationFilter->Setter<ParticleAggregationDirectionTag>(0.0f);
        particleAggregationFilter->Setter<ParticleAggregationMaxParticleCountTag>(10000.0f);

        auto backgroundNode = SetUpNodeBgImage(BG_PATH,
            {start, start + (start + nodeWidth) * i, nodeWidth * (i + 1), nodeHeight * (i + 1)});
        backgroundNode->SetForegroundNGFilter(particleAggregationFilter);
        GetRootNode()->AddChild(backgroundNode);
        RegisterNode(backgroundNode);
    }
}

GRAPHIC_TEST(NGFilterParticleAggregationTest, EFFECT_TEST, Set_NG_Filter_Particle_Aggregation_Direction_Test)
{
    int nodeWidth = 200;
    int nodeHeight = 200;
    int start = 50;
    int row = 4;
    std::vector<float> directionValues = {0.0f, 1.0f, 2.0f, 3.0f};

    for (int i = 0; i < row; i++) {
        auto particleAggregationPtr = CreateFilter(RSNGEffectType::PARTICLE_AGGREGATION);
        auto particleAggregationFilter =
            std::static_pointer_cast<RSNGParticleAggregationFilter>(particleAggregationPtr);
        particleAggregationFilter->Setter<ParticleAggregationProgressTag>(0.5f);
        particleAggregationFilter->Setter<ParticleAggregationDirectionTag>(directionValues[i]);
        particleAggregationFilter->Setter<ParticleAggregationMaxParticleCountTag>(10000.0f);

        auto backgroundNode = SetUpNodeBgImage(BG_PATH,
            {start, start + (start + nodeWidth) * i, nodeWidth * (i + 1), nodeHeight * (i + 1)});
        backgroundNode->SetForegroundNGFilter(particleAggregationFilter);
        GetRootNode()->AddChild(backgroundNode);
        RegisterNode(backgroundNode);
    }
}

GRAPHIC_TEST(NGFilterParticleAggregationTest, EFFECT_TEST, Set_NG_Filter_Particle_Aggregation_MaxParticleCount_Test)
{
    int nodeWidth = 200;
    int nodeHeight = 200;
    int start = 50;
    int row = 4;
    std::vector<float> countValues = {1000.0f, 5000.0f, 10000.0f, 20000.0f};

    for (int i = 0; i < row; i++) {
        auto particleAggregationPtr = CreateFilter(RSNGEffectType::PARTICLE_AGGREGATION);
        auto particleAggregationFilter =
            std::static_pointer_cast<RSNGParticleAggregationFilter>(particleAggregationPtr);
        particleAggregationFilter->Setter<ParticleAggregationProgressTag>(0.5f);
        particleAggregationFilter->Setter<ParticleAggregationDirectionTag>(0.0f);
        particleAggregationFilter->Setter<ParticleAggregationMaxParticleCountTag>(countValues[i]);

        auto backgroundNode = SetUpNodeBgImage(BG_PATH,
            {start, start + (start + nodeWidth) * i, nodeWidth * (i + 1), nodeHeight * (i + 1)});
        backgroundNode->SetForegroundNGFilter(particleAggregationFilter);
        GetRootNode()->AddChild(backgroundNode);
        RegisterNode(backgroundNode);
    }
}
} // namespace OHOS::Rosen
