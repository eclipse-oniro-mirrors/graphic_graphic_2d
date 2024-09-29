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

#include "gtest/gtest.h"
#include "txt/text_style.h"
#include "symbol_engine/hm_symbol_node_build.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace SPText {
class OHHmSymbolNodeBuildTest : public testing::Test {
public:
    static bool SetSymbolAnimationOne(const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig);
    static bool SetSymbolAnimationTwo(const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig);
    std::vector<std::vector<size_t>> layers_ = {{0}, {1}}; // this two layers
    Drawing::DrawingAnimationSetting animationSettingOne_ = {
        // animationTypes
        {
            Drawing::DrawingAnimationType::SCALE_TYPE,
            Drawing::DrawingAnimationType::APPEAR_TYPE,
            Drawing::DrawingAnimationType::DISAPPEAR_TYPE,
            Drawing::DrawingAnimationType::BOUNCE_TYPE
        },
        // groupSettings
        {
            // {0, 1}: layerIndes, 0: animationIndex
            {{{{0, 1}}}, 0}
        }
    };
    Drawing::DrawingAnimationSetting animationSettingTwo_ = {
        // animationTypes
        {
            Drawing::DrawingAnimationType::SCALE_TYPE,
            Drawing::DrawingAnimationType::VARIABLE_COLOR_TYPE
        },
        // groupSettings
        {
            // {0} {1}: layerIndes, 0 1: animationIndex
            {{{{0}}}, 0}, {{{{1}}}, 1}
        }
    };
    Drawing::DrawingAnimationSetting animationSettingOneMask_ = {
        // animationTypes
        {
            Drawing::DrawingAnimationType::SCALE_TYPE,
            Drawing::DrawingAnimationType::VARIABLE_COLOR_TYPE,
            Drawing::DrawingAnimationType::BOUNCE_TYPE
        },
        // groupSettings
        {
            // {0, 2}: layerIndes, {1, 3}: maskIndexes 0: animationIndex
            {{{{0, 2}, {1, 3}}}, 0}
        }
    };
    Drawing::DrawingAnimationSetting animationSettingMaskLayer_ = {
        // animationTypes
        {
            Drawing::DrawingAnimationType::SCALE_TYPE,
            Drawing::DrawingAnimationType::VARIABLE_COLOR_TYPE,
            Drawing::DrawingAnimationType::BOUNCE_TYPE
        },
        // groupSettings
        {
            // {0} {}: layerIndes, {1, 2}: maskIndexes 0 1: animationIndex
            {{{{0}}}, 0}, {{{{}, {1, 2}}}, 1}
        }
    };

    // the {0, 1} is layerIndexes of one group
    std::vector<Drawing::DrawingRenderGroup> renderGroupsOne_ = {{{{{0, 1}}}}};
    // the {0, 2} is layerIndexes, {1, 3} is maskIndexes of one group
    std::vector<Drawing::DrawingRenderGroup> renderGroupsOneMask_ = {{{{{0, 2}, {1, 3}}}}};
    // the {0} {1} is layerIndexes of two group
    std::vector<Drawing::DrawingRenderGroup> renderGroupsTwo_ = {{{{{0}}}}, {{{{1}}}}};
    // the {0},{} is layerIndexes  {1, 2}is maskIndexes of two group
    std::vector<Drawing::DrawingRenderGroup> renderGroupsMaskLayer_ = {{{{{0}}}}, {{{{}, {1, 2}}}}};
};

bool OHHmSymbolNodeBuildTest::SetSymbolAnimationOne(
    const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig)
{
    if (symbolAnimationConfig == nullptr) {
        return false;
    }

    // check the size is 1 of nodes config
    if (symbolAnimationConfig->numNodes == 1 && symbolAnimationConfig->symbolNodes.size() == 1) {
        return true;
    }
    return false;
}

bool OHHmSymbolNodeBuildTest::SetSymbolAnimationTwo(
    const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig)
{
    if (symbolAnimationConfig == nullptr) {
        return false;
    }

    // check the size is 2 of nodes config
    if (symbolAnimationConfig->numNodes == 2 && symbolAnimationConfig->symbolNodes.size() == 2) {
        return true;
    }
    return false;
}

/*
 * @tc.name: SymbolNodeBuild001
 * @tc.desc: test SymbolNodeBuild with simulation data
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, SymbolNodeBuild001, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSAnimationSetting animationSetting;
    RSHMSymbolData symbol;
    RSEffectStrategy effectMode = RSEffectStrategy::SCALE;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSetting, symbol, effectMode, offset);
    EXPECT_EQ(symbolNode.effectStrategy_, RSEffectStrategy::SCALE);
}

/*
 * @tc.name: DecomposeSymbolAndDraw001
 * @tc.desc: test DecomposeSymbolAndDraw with animation SCALE and wholeSymbol effect
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw001, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 40); // 100 x, 100, 40 radius
    path.AddCircle(100, 100, 30, Drawing::PathDirection::CCW_DIRECTION); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsOne_;

    RSEffectStrategy effectMode = RSEffectStrategy::SCALE;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingOne_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationOne);
    symbolNode.SetSymbolId(0);
    symbolNode.SetAnimationMode(1); // 1 is wholeSymbol effect
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: DecomposeSymbolAndDraw002
 * @tc.desc: test DecomposeSymbolAndDraw with animation SCALE and byLayer effect
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw002, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 50); // 100 x, 100, 50 radius
    path.AddCircle(100, 100, 30, Drawing::PathDirection::CCW_DIRECTION); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsTwo_;

    RSEffectStrategy effectMode = RSEffectStrategy::SCALE;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingTwo_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationTwo);
    symbolNode.SetSymbolId(0);
    symbolNode.SetAnimationMode(0); // 0 is byLayer effect
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: DecomposeSymbolAndDraw003
 * @tc.desc: test DecomposeSymbolAndDraw with animation BOUNCE, wholeSymbol effect and maskLayer
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw003, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 65); // 100 x, 100, 40 radius
    path.AddCircle(100, 100, 45); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsOneMask_;

    RSEffectStrategy effectMode = RSEffectStrategy::BOUNCE;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingOne_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationOne);
    symbolNode.SetSymbolId(0);
    symbolNode.SetAnimationMode(1); // 1 is wholeSymbol effect
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: DecomposeSymbolAndDraw004
 * @tc.desc: test DecomposeSymbolAndDraw with animation VARIABLE_COLOR and iteratuve effect
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw004, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 50); // 100 x, 100, 50 radius
    path.AddCircle(100, 100, 30, Drawing::PathDirection::CCW_DIRECTION); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsTwo_;

    RSEffectStrategy effectMode = RSEffectStrategy::VARIABLE_COLOR;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingTwo_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationTwo);
    symbolNode.SetSymbolId(0);
    symbolNode.SetAnimationMode(1); // 0 is iteratuve effect
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: DecomposeSymbolAndDraw005
 * @tc.desc: test DecomposeSymbolAndDraw with animation BOUNCE, byLayer effect and has maskLayers
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw005, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 50); // 100 x, 100, 50 radius
    path.AddCircle(100, 100, 30, Drawing::PathDirection::CCW_DIRECTION); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsMaskLayer_;

    RSEffectStrategy effectMode = RSEffectStrategy::BOUNCE;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingMaskLayer_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationTwo);
    symbolNode.SetAnimationMode(0); // 0 is byLayer effect
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: DecomposeSymbolAndDraw006
 * @tc.desc: test DecomposeSymbolAndDraw with animation VARIABLE_COLOR, cumulative effect and maskIndexes
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw006, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 65); // 100 x, 100, 40 radius
    path.AddCircle(100, 100, 45); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsOneMask_;

    RSEffectStrategy effectMode = RSEffectStrategy::VARIABLE_COLOR;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingOneMask_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationOne);
    symbolNode.SetAnimationMode(0); // 1 is cumulative effect
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);

    // test animation REPLACE_DISAPPEAR
    effectMode = RSEffectStrategy::REPLACE_DISAPPEAR;
    SymbolNodeBuild symbolNode1 = SymbolNodeBuild(animationSettingOneMask_, symbol, effectMode, offset);
    symbolNode1.SetAnimation(&SetSymbolAnimationOne);
    symbolNode1.SetAnimationMode(1); // 1 is cumulative effect
    int result1 = symbolNode1.DecomposeSymbolAndDraw();
    EXPECT_EQ(result1, true);

    // test animationFunc is nullptr
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    symbolNode.SetAnimation(animationFunc);
    int result2 = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result2, false);
}

/*
 * @tc.name: DecomposeSymbolAndDraw007
 * @tc.desc: test DecomposeSymbolAndDraw with animation VARIABLE_COLOR, two rendergroups and only one animationGroup
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, DecomposeSymbolAndDraw007, TestSize.Level1)
{
    std::pair<double, double> offset = {100, 100}; // 100, 100 is the offset
    RSPath path;
    path.AddCircle(100, 100, 50); // 100 x, 100, 50 radius
    path.AddCircle(100, 100, 30, Drawing::PathDirection::CCW_DIRECTION); // 100 x, 100, 30 radius
    RSHMSymbolData symbol;
    symbol.path_ = path;
    symbol.symbolInfo_.layers = layers_;
    symbol.symbolInfo_.renderGroups = renderGroupsTwo_;

    RSEffectStrategy effectMode = RSEffectStrategy::VARIABLE_COLOR;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingOne_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationOne);
    int result = symbolNode.DecomposeSymbolAndDraw();
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: ClearAnimation001
 * @tc.desc: test ClearAnimation with animation VARIABLE_COLOR, cumulative effect and maskIndexes
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolNodeBuildTest, ClearAnimation001, TestSize.Level1)
{
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    RSHMSymbolData symbol;

    RSEffectStrategy effectMode = RSEffectStrategy::NONE;
    SymbolNodeBuild symbolNode = SymbolNodeBuild(animationSettingOneMask_, symbol, effectMode, offset);
    symbolNode.SetAnimation(&SetSymbolAnimationOne);
    symbolNode.ClearAnimation();
    EXPECT_EQ(symbolNode.effectStrategy_, RSEffectStrategy::NONE);
}
} // namespace SPText
} // namespace Rosen
} // namespace OHOS