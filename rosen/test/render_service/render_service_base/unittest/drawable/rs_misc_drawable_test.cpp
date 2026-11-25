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

#include "drawable/rs_blender_drawable_utils.h"
#include "drawable/rs_misc_drawable.h"
#include "effect/rs_render_blender_base.h"
#include "drawable/rs_render_node_drawable_adapter.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "pipeline/rs_render_node.h"
#include "modifier_ng/foreground/rs_env_foreground_color_render_modifier.h"
#include "property/rs_properties.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSChildrenDrawableTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static void DisplayTestInfo();
};

class ConcreteRSRenderNodeDrawableAdapter : public DrawableV2::RSRenderNodeDrawableAdapter {
public:
    explicit ConcreteRSRenderNodeDrawableAdapter(std::shared_ptr<const RSRenderNode> node)
        : RSRenderNodeDrawableAdapter(std::move(node))
    {}
    void Draw(Drawing::Canvas& canvas) {}
};

void RSChildrenDrawableTest::SetUpTestCase() {}
void RSChildrenDrawableTest::TearDownTestCase() {}
void RSChildrenDrawableTest::SetUp() {}
void RSChildrenDrawableTest::TearDown() {}

/**
 * @tc.name: RSChildrenDrawable001
 * @tc.desc: Test OnGenerate
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSChildrenDrawable001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    std::shared_ptr<RSRenderNode> childOne = std::make_shared<RSRenderNode>(2);
    std::shared_ptr<RSRenderNode> childTwo = std::make_shared<RSRenderNode>(3);
    std::shared_ptr<RSRenderNode> childThree = std::make_shared<RSRenderNode>(4);
    std::shared_ptr<RSRenderNode> childFour = std::make_shared<RSRenderNode>(5);
    std::shared_ptr<RSRenderNode> childFive = std::make_shared<RSRenderNode>(6);
    ASSERT_EQ(DrawableV2::RSChildrenDrawable::OnGenerate(node), nullptr);

    std::shared_ptr<RSRenderNode> inNode = std::make_shared<RSRenderNode>(2);
    std::shared_ptr<RSRenderNode> outNode = std::make_shared<RSRenderNode>(2);
    outNode->isOnTheTree_ = true;
    auto sharedTransitionParam = std::make_shared<SharedTransitionParam>(inNode, outNode, true);
    sharedTransitionParam->relation_ = SharedTransitionParam::NodeHierarchyRelation::IN_NODE_BELOW_OUT_NODE;

    ASSERT_TRUE(sharedTransitionParam->IsLower(childOne->GetId()));
    childOne->SetSharedTransitionParam(sharedTransitionParam);
    ASSERT_TRUE(LIKELY(!node.GetRenderProperties().GetUseShadowBatching()));
    node.AddChild(childOne, -1);
    node.AddChild(childTwo, -1);
    node.AddChild(childThree, -1);
    node.AddChild(childFour, -1);
    node.AddChild(childFive, -1);
    node.disappearingChildren_.emplace_back(childOne, 1);
    node.disappearingChildren_.emplace_back(childTwo, 2);
    node.disappearingChildren_.emplace_back(childThree, 3);
    node.disappearingChildren_.emplace_back(childFour, 4);
    node.disappearingChildren_.emplace_back(childFive, 5);
    node.GenerateFullChildrenList();
    ASSERT_TRUE(node.fullChildrenList_->size());

    ASSERT_TRUE(UNLIKELY(childOne->GetSharedTransitionParam()));
    ASSERT_FALSE(UNLIKELY(childTwo->GetSharedTransitionParam()));
    ASSERT_FALSE(UNLIKELY(childThree->GetSharedTransitionParam()));
    ASSERT_FALSE(UNLIKELY(childFour->GetSharedTransitionParam()));
    ASSERT_FALSE(UNLIKELY(childFive->GetSharedTransitionParam()));
    ASSERT_EQ(DrawableV2::RSChildrenDrawable::OnGenerate(node), nullptr);

    node.GetMutableRenderProperties().SetUseShadowBatching(true);
    ASSERT_FALSE(LIKELY(!node.GetRenderProperties().GetUseShadowBatching()));
    auto nodeTwo = std::make_shared<RSRenderNode>(0);
    auto nodeDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(nodeTwo);
    childThree->renderDrawable_ = nodeDrawable;

    auto nodeThree = std::make_shared<RSRenderNode>(10);
    auto nodeDrawableThree = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(nodeThree);
    childFour->renderDrawable_ = nodeDrawableThree;

    auto nodeFour = std::make_shared<RSRenderNode>(11);
    auto nodeDrawableFour = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(nodeFour);
    childFive->renderDrawable_ = nodeDrawableFour;
    ASSERT_NE(DrawableV2::RSChildrenDrawable::OnGenerate(node), nullptr);

    node.GetMutableRenderProperties().SetUseShadowBatching(false);
    auto drawable =
        std::static_pointer_cast<DrawableV2::RSChildrenDrawable>(DrawableV2::RSChildrenDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    ASSERT_TRUE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);

    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    EXPECT_NE(canvas, nullptr);
}

/**
 * @tc.name: RSChildrenDrawable002
 * @tc.desc: Test OnSharedTransition
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSChildrenDrawable002, TestSize.Level1)
{
    NodeId id = 1;
    auto node = std::make_shared<RSRenderNode>(id);
    std::shared_ptr<RSRenderNode> inNode = std::make_shared<RSRenderNode>(1);
    std::shared_ptr<RSRenderNode> outNode = std::make_shared<RSRenderNode>(1);
    auto sharedTransitionParam = std::make_shared<SharedTransitionParam>(inNode, outNode, true);
    node->sharedTransitionParam_ = sharedTransitionParam;
    DrawableV2::RSChildrenDrawable childrenDrawable;
    ASSERT_FALSE(childrenDrawable.OnSharedTransition(node));
    inNode->isOnTheTree_ = true;
    outNode->isOnTheTree_ = true;
    ASSERT_FALSE(childrenDrawable.OnSharedTransition(node));
    sharedTransitionParam = std::make_shared<SharedTransitionParam>(inNode, outNode, true);
    node->sharedTransitionParam_ = sharedTransitionParam;
    ASSERT_TRUE(childrenDrawable.OnSharedTransition(node));
    inNode->isOnTheTree_ = false;
    inNode->SetIsOnTheTree(true, 1);
    auto nodeTwo = std::make_shared<RSRenderNode>(0);
    auto nodeDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(nodeTwo);
    outNode->renderDrawable_ = nodeDrawable;
    sharedTransitionParam = std::make_shared<SharedTransitionParam>(inNode, outNode, true);
    node->sharedTransitionParam_ = sharedTransitionParam;
    ASSERT_TRUE(childrenDrawable.OnSharedTransition(node));
}

/**
 * @tc.name: RSCustomModifierDrawable002
 * @tc.desc: Test OnDraw for RSCustomModifierDrawable
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomModifierDrawable002, TestSize.Level1)
{
    auto node = std::make_shared<RSCanvasDrawingRenderNode>(1);
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(
        DrawableV2::RSCustomModifierDrawable::OnGenerate(*node, ModifierNG::RSModifierType::CONTENT_STYLE), nullptr);

    auto drawCmdList = std::make_shared<RSSimpleDrawCmdList>();
    auto property = std::make_shared<RSRenderProperty<SimpleDrawCmdListPtr>>();
    property->GetRef() = drawCmdList;
    auto modifier1 = std::make_shared<ModifierNG::RSCustomRenderModifier<ModifierNG::RSModifierType::CONTENT_STYLE>>();
    ASSERT_NE(modifier1, nullptr);
    modifier1->properties_[ModifierNG::RSPropertyType::CONTENT_STYLE] = property;
    auto indexProperty = std::make_shared<RSRenderProperty<int16_t>>(2, 0);
    modifier1->properties_[ModifierNG::RSPropertyType::CUSTOM_INDEX] = indexProperty;
    node->AddModifier(modifier1);

    auto propertyTwo = std::make_shared<RSRenderProperty<SimpleDrawCmdListPtr>>();
    propertyTwo->GetRef() = std::make_shared<RSSimpleDrawCmdList>(1, 1);
    auto modifier2 = std::make_shared<ModifierNG::RSCustomRenderModifier<ModifierNG::RSModifierType::CONTENT_STYLE>>();
    ASSERT_NE(modifier2, nullptr);
    modifier2->properties_[ModifierNG::RSPropertyType::CONTENT_STYLE] = propertyTwo;
    auto indexProperty2 = std::make_shared<RSRenderProperty<int16_t>>(1, 1);
    modifier2->properties_[ModifierNG::RSPropertyType::CUSTOM_INDEX] = indexProperty2;
    node->AddModifier(modifier2);

    node->AddDirtyType(ModifierNG::RSModifierType::CONTENT_STYLE);
    auto drawable = std::static_pointer_cast<DrawableV2::RSCustomModifierDrawable>(
        DrawableV2::RSCustomModifierDrawable::OnGenerate(*node, ModifierNG::RSModifierType::CONTENT_STYLE));
    ASSERT_NE(drawable, nullptr);

    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();

    drawable->OnSync();
    drawable->needClearOp_ = true;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::INVALID;
    drawable->OnDraw(canvas.get(), rect.get());

    drawable->needClearOp_ = false;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::INVALID;
    drawable->OnDraw(canvas.get(), rect.get());

    drawable->needClearOp_ = true;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::CONTENT_STYLE;
    drawable->OnDraw(canvas.get(), rect.get());

    drawable->needClearOp_ = false;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::CONTENT_STYLE;
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_NE(drawable, nullptr);

    node->GetMutableRenderProperties().SetFrameGravity(Gravity::CENTER);
    auto customModifiers = node->GetModifiersNG(drawable->modifierTypeNG_);
    EXPECT_EQ(customModifiers.empty(), false);
    drawable->OnUpdate(*node);
    drawable->OnSync();
    EXPECT_EQ(drawable->isCanvasNode_, false);
    EXPECT_EQ(drawable->gravity_, Gravity::CENTER);
    drawable->needClearOp_ = true;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::CONTENT_STYLE;
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_NE(drawable, nullptr);
}

/**
 * @tc.name: RSCustomModifierDrawable003
 * @tc.desc: Test OnDraw for RSCustomModifierDrawable on isCanvasNode_ = true branch;
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomModifierDrawable003, TestSize.Level1)
{
    auto node = std::make_shared<RSCanvasDrawingRenderNode>(1);
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(
        DrawableV2::RSCustomModifierDrawable::OnGenerate(*node, ModifierNG::RSModifierType::CONTENT_STYLE), nullptr);

    auto drawCmdList = std::make_shared<RSSimpleDrawCmdList>();
    auto property = std::make_shared<RSRenderProperty<SimpleDrawCmdListPtr>>();
    property->GetRef() = drawCmdList;

    auto modifier1 = std::make_shared<ModifierNG::RSCustomRenderModifier<ModifierNG::RSModifierType::CONTENT_STYLE>>();
    ASSERT_NE(modifier1, nullptr);
    modifier1->properties_[ModifierNG::RSPropertyType::CONTENT_STYLE] = property;
    auto indexProperty = std::make_shared<RSRenderProperty<int16_t>>(2, 0);
    modifier1->properties_[ModifierNG::RSPropertyType::CUSTOM_INDEX] = indexProperty;
    node->AddModifier(modifier1);

    auto propertyTwo = std::make_shared<RSRenderProperty<SimpleDrawCmdListPtr>>();
    propertyTwo->GetRef() = std::make_shared<RSSimpleDrawCmdList>(1, 1);
    auto modifier2 = std::make_shared<ModifierNG::RSCustomRenderModifier<ModifierNG::RSModifierType::CONTENT_STYLE>>();
    ASSERT_NE(modifier2, nullptr);
    modifier2->properties_[ModifierNG::RSPropertyType::CONTENT_STYLE] = propertyTwo;
    auto indexProperty2 = std::make_shared<RSRenderProperty<int16_t>>(1, 1);
    modifier2->properties_[ModifierNG::RSPropertyType::CUSTOM_INDEX] = indexProperty2;
    node->AddModifier(modifier2);
    node->AddDirtyType(ModifierNG::RSModifierType::CONTENT_STYLE);
    auto drawable = std::static_pointer_cast<DrawableV2::RSCustomModifierDrawable>(
        DrawableV2::RSCustomModifierDrawable::OnGenerate(*node, ModifierNG::RSModifierType::CONTENT_STYLE));
    ASSERT_NE(drawable, nullptr);

    drawable->isCanvasNode_ = true;
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();

    drawable->needClearOp_ = true;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::CONTENT_STYLE;
    drawable->OnDraw(canvas.get(), rect.get());

    drawable->needClearOp_ = false;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::CONTENT_STYLE;
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_NE(drawable, nullptr);

    node->GetMutableRenderProperties().SetFrameGravity(Gravity::CENTER);
    auto customModifiers = node->GetModifiersNG(drawable->modifierTypeNG_);
    EXPECT_EQ(customModifiers.empty(), false);
    drawable->OnUpdate(*node);
    drawable->OnSync();
    EXPECT_EQ(drawable->isCanvasNode_, false);
    EXPECT_EQ(drawable->gravity_, Gravity::CENTER);
    drawable->needClearOp_ = true;
    drawable->modifierTypeNG_ = ModifierNG::RSModifierType::CONTENT_STYLE;
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_NE(drawable, nullptr);
}

/**
 * @tc.name: RSBeginBlenderDrawable001
 * @tc.desc: Test OnGenerate
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    node.GetMutableRenderProperties().SetColorBlendMode(12);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);

    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSBeginBlenderDrawable003
 * @tc.desc: Test OnDraw for RSBeginBlenderDrawable
 * @tc.type:FUNC
 * @tc.require: issueICLU4I
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable003, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    node.GetMutableRenderProperties().SetColorBlendMode(12);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();

    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    EXPECT_NE(canvas, nullptr);

    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    drawable->OnDraw(filterCanvas.get(), rect.get());
    EXPECT_NE(filterCanvas->envStack_.top().blender_, nullptr);
}

/**
 * @tc.name: RSBeginBlenderDrawable008
 * @tc.desc: Test OnGenerate/OnUpdate for the NG blender path. Covers the store-only NG object,
 *           the RSBlenderDrawableUtils unpacking (MakeColorfulBrightnessFromNG), NG-over-legacy
 *           priority in OnUpdate, and the NG EDR check in PostUpdate.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable008, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto colorfulBlender = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(ngBlender);
    colorfulBlender->Setter<ColorfulBrightnessBlenderDarkenWeightRenderTag>(1.0f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderFractionRenderTag>(0.5f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderCubicRateRenderTag>(0.1f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderQuadRateRenderTag>(0.2f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderLinearRateRenderTag>(0.3f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderDegreeRenderTag>(0.4f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderSaturationRenderTag>(0.5f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderPositiveCoeffRenderTag>(Vector3f(0.6f, 0.7f, 0.8f));
    colorfulBlender->Setter<ColorfulBrightnessBlenderNegativeCoeffRenderTag>(Vector3f(0.9f, 0.1f, 0.2f));
    colorfulBlender->Setter<ColorfulBrightnessBlenderVibrancyStrengthRenderTag>(0.33f);
    colorfulBlender->Setter<ColorfulBrightnessBlenderLumaDiffRenderTag>(0.88f);
    // legacy flat params use hdrEnabled_ = false; NG uses true, so EDR can only come from the NG path
    colorfulBlender->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    colorfulBlender->Setter<ColorfulBrightnessBlenderTintedColorPercentRenderTag>(0.66f);

    node.GetMutableRenderProperties().SetNGBlender(ngBlender);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    // NG EDR check: hdrEnabled_ is only true on the NG side
    ASSERT_TRUE(drawable->GetEnableEDR());
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);

    // clear NG: no legacy flat fallback exists any more, the drawable must not regenerate
    node.GetMutableRenderProperties().SetNGBlender(nullptr);
    auto drawableLegacy = DrawableV2::RSBeginBlenderDrawable::OnGenerate(node);
    ASSERT_EQ(drawableLegacy, nullptr);
}

/**
 * @tc.name: RSBeginBlenderDrawable009
 * @tc.desc: Test OnGenerate/OnUpdate for the NG BRIGHTNESS_BLENDER path. Covers the
 *           RSBlenderDrawableUtils unpacking (MakeBrightnessFromNG packs 9 tags into
 *           RSDynamicBrightnessPara) and the NG EDR check driven by the HdrEnabled tag.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable009, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto brightnessBlender = std::static_pointer_cast<RSNGRenderBrightnessBlender>(ngBlender);
    brightnessBlender->Setter<BrightnessBlenderFractionRenderTag>(0.5f);
    brightnessBlender->Setter<BrightnessBlenderCubicRateRenderTag>(0.1f);
    brightnessBlender->Setter<BrightnessBlenderQuadRateRenderTag>(0.2f);
    brightnessBlender->Setter<BrightnessBlenderLinearRateRenderTag>(0.3f);
    brightnessBlender->Setter<BrightnessBlenderDegreeRenderTag>(0.4f);
    brightnessBlender->Setter<BrightnessBlenderSaturationRenderTag>(0.5f);
    brightnessBlender->Setter<BrightnessBlenderPositiveCoeffRenderTag>(Vector3f(0.6f, 0.7f, 0.8f));
    brightnessBlender->Setter<BrightnessBlenderNegativeCoeffRenderTag>(Vector3f(0.9f, 0.1f, 0.2f));
    brightnessBlender->Setter<BrightnessBlenderHdrEnabledRenderTag>(true);

    node.GetMutableRenderProperties().SetNGBlender(ngBlender);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    // NG EDR check: hdrEnabled tag is true only on the NG side
    ASSERT_TRUE(drawable->GetEnableEDR());
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);

    // clear NG: no legacy flat fallback for this node, drawable is not generated any more
    node.GetMutableRenderProperties().SetNGBlender(nullptr);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);
}

/**
 * @tc.name: RSBeginBlenderDrawable010
 * @tc.desc: Test OnGenerate/OnUpdate for the NG HDR_DARKEN_BLENDER path. Covers the
 *           RSBlenderDrawableUtils unpacking (MakeHdrDarkenFromNG builds RSHdrDarkenBlenderPara from
 *           2 tags). HDR darken has no EDR switch, so GetEnableEDR stays false.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable010, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::HDR_DARKEN_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto hdrDarkenBlender = std::static_pointer_cast<RSNGRenderHdrDarkenBlender>(ngBlender);
    hdrDarkenBlender->Setter<HdrDarkenBlenderHdrBrightnessRatioRenderTag>(2.0f);
    hdrDarkenBlender->Setter<HdrDarkenBlenderGrayscaleFactorRenderTag>(Vector3f(0.299f, 0.587f, 0.114f));

    node.GetMutableRenderProperties().SetNGBlender(ngBlender);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    ASSERT_FALSE(drawable->GetEnableEDR());
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);

    // clear NG: no legacy flat fallback for this node, drawable is not generated any more
    node.GetMutableRenderProperties().SetNGBlender(nullptr);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);
}

/**
 * @tc.name: RSBeginBlenderDrawable012
 * @tc.desc: Test the invalid-parameter fallback of the NG BRIGHTNESS_BLENDER path:
 *           fraction == 1.0 makes MakeBrightnessFromNG return nullptr (mirroring the
 *           legacy IsFgBrightnessValid gate), OnUpdate falls back to the blendMode path.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable012, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);

    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto brightnessBlender = std::static_pointer_cast<RSNGRenderBrightnessBlender>(ngBlender);
    // fraction == 1.0 means no fg brightness effect
    brightnessBlender->Setter<BrightnessBlenderFractionRenderTag>(1.0f);
    node.GetMutableRenderProperties().SetNGBlender(ngBlender);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    // with blendMode set, the invalid NG blender falls back to the blendMode path
    node.GetMutableRenderProperties().SetColorBlendMode(12);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    ASSERT_FALSE(drawable->GetEnableEDR());
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSBlenderDrawableUtilsMakeBlenderFromNG001
 * @tc.desc: Test RSBlenderDrawableUtils::MakeBlenderFromNG entry checks and all registered types:
 *           nullptr input returns nullptr, the 3 registered types return a non-null Drawing blender.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBlenderDrawableUtilsMakeBlenderFromNG001, TestSize.Level1)
{
    // nullptr entry check (OnUpdate guards it, so it is only reachable via a direct call)
    EXPECT_EQ(RSBlenderDrawableUtils::MakeBlenderFromNG(nullptr), nullptr);

    EXPECT_NE(RSBlenderDrawableUtils::MakeBlenderFromNG(
                  RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER)),
        nullptr);
    EXPECT_NE(RSBlenderDrawableUtils::MakeBlenderFromNG(
                  RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER)),
        nullptr);
    EXPECT_NE(RSBlenderDrawableUtils::MakeBlenderFromNG(
                  RSNGRenderBlenderBase::Create(RSNGEffectType::HDR_DARKEN_BLENDER)),
        nullptr);
}

/**
 * @tc.name: RSBlenderDrawableUtilsMakeBlenderFromNGUnknownType001
 * @tc.desc: Test the unregistered-type branch of MakeBlenderFromNG: a blender whose GetType() has
 *           no maker in the LUT falls back to nullptr (the caller then uses the blendMode path).
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBlenderDrawableUtilsMakeBlenderFromNGUnknownType001, TestSize.Level1)
{
    // test-local type without a registered maker (all shipped types are registered)
    using RSNGRenderUnknownBlender = RSNGRenderBlenderTemplate<RSNGEffectType::NONE>;
    auto unknownBlender = std::make_shared<RSNGRenderUnknownBlender>();
    ASSERT_NE(unknownBlender, nullptr);
    EXPECT_EQ(unknownBlender->GetType(), RSNGEffectType::NONE);
    EXPECT_EQ(RSBlenderDrawableUtils::MakeBlenderFromNG(unknownBlender), nullptr);
}

/**
 * @tc.name: RSBlenderDrawableUtilsGetNGBlenderEnableEDR001
 * @tc.desc: Test all branches of RSBlenderDrawableUtils::GetNGBlenderEnableEDR: no blender,
 *           colorful/brightness blenders driven by their HdrEnabled tag, and other types
 *           (no EDR switch) returning false.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBlenderDrawableUtilsGetNGBlenderEnableEDR001, TestSize.Level1)
{
    RSProperties properties;
    // no NG blender stored
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGBlenderEnableEDR(properties));

    // colorful blender: EDR follows the HdrEnabled tag
    auto colorfulBlender = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(
        RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER));
    ASSERT_NE(colorfulBlender, nullptr);
    properties.SetNGBlender(colorfulBlender);
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGBlenderEnableEDR(properties));
    colorfulBlender->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    EXPECT_TRUE(RSBlenderDrawableUtils::GetNGBlenderEnableEDR(properties));

    // brightness blender: EDR follows the HdrEnabled tag
    auto brightnessBlender = std::static_pointer_cast<RSNGRenderBrightnessBlender>(
        RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER));
    ASSERT_NE(brightnessBlender, nullptr);
    properties.SetNGBlender(brightnessBlender);
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGBlenderEnableEDR(properties));
    brightnessBlender->Setter<BrightnessBlenderHdrEnabledRenderTag>(true);
    EXPECT_TRUE(RSBlenderDrawableUtils::GetNGBlenderEnableEDR(properties));

    // other blender types have no EDR switch
    properties.SetNGBlender(RSNGRenderBlenderBase::Create(RSNGEffectType::HDR_DARKEN_BLENDER));
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGBlenderEnableEDR(properties));
}

/**
 * @tc.name: RSBlenderDrawableUtilsMakeDynamicBrightnessBlender001
 * @tc.desc: Test RSBlenderDrawableUtils::MakeDynamicBrightnessBlender branch selection by direct
 *           calls: the linear case (rates.x==0 && rates.y==0 && fraction==0) with both swap
 *           outcomes (minusSat>0 / minusSat<=0) and the non-linear case with enableHdr on/off.
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSChildrenDrawableTest, RSBlenderDrawableUtilsMakeDynamicBrightnessBlender001, TestSize.Level1)
{
    // linear case, minusSat > 0: posCoeff/negCoeff keep their order
    RSDynamicBrightnessPara linearSwapFalse;
    linearSwapFalse.rates_ = Vector4f(0.0f, 0.0f, 1.0f, 1.0f);
    linearSwapFalse.fraction_ = 0.0f;
    linearSwapFalse.saturation_ = 0.5f;
    EXPECT_NE(RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(linearSwapFalse), nullptr);

    // linear case, minusSat <= 0: posCoeff/negCoeff are swapped
    RSDynamicBrightnessPara linearSwapTrue;
    linearSwapTrue.rates_ = Vector4f(0.0f, 0.0f, 1.0f, 1.0f);
    linearSwapTrue.fraction_ = 0.0f;
    linearSwapTrue.saturation_ = 1.5f;
    EXPECT_NE(RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(linearSwapTrue), nullptr);

    // non-linear case, enableHdr off: headroom stays 1.0
    RSDynamicBrightnessPara nonLinearHdrOff;
    nonLinearHdrOff.rates_ = Vector4f(0.1f, 0.2f, 0.3f, 0.4f);
    nonLinearHdrOff.fraction_ = 0.5f;
    nonLinearHdrOff.saturation_ = 0.5f;
    EXPECT_NE(RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(nonLinearHdrOff), nullptr);

    // non-linear case, enableHdr on: headroom becomes EFFECT_MAX_LUMINANCE
    RSDynamicBrightnessPara nonLinearHdrOn;
    nonLinearHdrOn.rates_ = Vector4f(0.1f, 0.2f, 0.3f, 0.4f);
    nonLinearHdrOn.fraction_ = 0.5f;
    nonLinearHdrOn.saturation_ = 0.5f;
    nonLinearHdrOn.enableHdr_ = true;
    EXPECT_NE(RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(nonLinearHdrOn), nullptr);

    // short-circuit arm of the linear condition: rates.x==0 with rates.y!=0 (second operand false)
    RSDynamicBrightnessPara secondOperandFalse;
    secondOperandFalse.rates_ = Vector4f(0.0f, 0.2f, 0.3f, 0.4f);
    secondOperandFalse.fraction_ = 0.5f;
    secondOperandFalse.saturation_ = 0.5f;
    EXPECT_NE(RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(secondOperandFalse), nullptr);

    // short-circuit arm of the linear condition: rates.x==0 && rates.y==0 with fraction!=0 (third operand false)
    RSDynamicBrightnessPara thirdOperandFalse;
    thirdOperandFalse.rates_ = Vector4f(0.0f, 0.0f, 0.3f, 0.4f);
    thirdOperandFalse.fraction_ = 0.5f;
    thirdOperandFalse.saturation_ = 0.5f;
    EXPECT_NE(RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(thirdOperandFalse), nullptr);
}

/**
 * @tc.name: RSEndBlenderDrawable001
 * @tc.desc: Test OnGenerate
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSEndBlenderDrawable001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSEndBlenderDrawable::OnGenerate(node), nullptr);
    node.GetMutableRenderProperties().SetColorBlendMode(12);
    ASSERT_EQ(DrawableV2::RSEndBlenderDrawable::OnGenerate(node), nullptr);
    node.GetMutableRenderProperties().SetColorBlendApplyType(2);
    auto drawable = std::static_pointer_cast<DrawableV2::RSEndBlenderDrawable>(
        DrawableV2::RSEndBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSEndBlenderDrawable002
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSEndBlenderDrawable002, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSEndBlenderDrawable>();
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(filterCanvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSEnvFGColorDrawable001
 * @tc.desc: Test OnGenerate
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSEnvFGColorDrawable001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSEnvFGColorDrawable::OnGenerate(node), nullptr);
    auto drawCmdList = std::make_shared<RSSimpleDrawCmdList>();
    auto property = std::make_shared<RSRenderProperty<SimpleDrawCmdListPtr>>();
    property->GetRef() = drawCmdList;
    auto modifier = std::make_shared<ModifierNG::RSEnvForegroundColorRenderModifier>();
    modifier->AttachProperty(ModifierNG::RSPropertyType::ENV_FOREGROUND_COLOR, property);
    node.AddModifier(modifier);
    node.GetMutableRenderProperties().SetColorBlendApplyType(2);
    auto drawable =
        std::static_pointer_cast<DrawableV2::RSEnvFGColorDrawable>(DrawableV2::RSEnvFGColorDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSEnvFGColorDrawable002
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSEnvFGColorDrawable002, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSEnvFGColorDrawable>();
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(filterCanvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSEnvFGColorStrategyDrawable001
 * @tc.desc: Test OnGenerate
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSEnvFGColorStrategyDrawable001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSEnvFGColorStrategyDrawable::OnGenerate(node), nullptr);
    auto drawCmdList = std::make_shared<RSSimpleDrawCmdList>();
    auto property = std::make_shared<RSRenderProperty<SimpleDrawCmdListPtr>>();
    property->GetRef() = drawCmdList;
    auto modifier = std::make_shared<ModifierNG::RSEnvForegroundColorRenderModifier>();
    modifier->AttachProperty(ModifierNG::RSPropertyType::ENV_FOREGROUND_COLOR_STRATEGY, property);
    node.AddModifier(modifier);
    auto drawable = std::static_pointer_cast<DrawableV2::RSEnvFGColorStrategyDrawable>(
        DrawableV2::RSEnvFGColorStrategyDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSEnvFGColorStrategyDrawable002
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSEnvFGColorStrategyDrawable002, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSEnvFGColorStrategyDrawable>();
    auto surface = std::make_shared<Drawing::Surface>();
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    filterCanvas->surface_ = surface.get();
    auto rect = std::make_shared<Drawing::Rect>(0, 0, 10, 10);
    drawable->OnDraw(filterCanvas.get(), rect.get());
    ASSERT_TRUE(true);
    drawable->envFGColorStrategy_ = ForegroundColorStrategyType::INVERT_BACKGROUNDCOLOR;
    drawable->OnDraw(filterCanvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSCustomClipToFrameDrawable002
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomClipToFrameDrawable002, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSCustomClipToFrameDrawable>();
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(filterCanvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSSaveDrawable001
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSSaveDrawable001, TestSize.Level1)
{
    auto count = std::make_shared<uint32_t>(std::numeric_limits<uint32_t>::max());
    auto drawable = std::make_shared<DrawableV2::RSSaveDrawable>(count);
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSRestoreDrawable001
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRestoreDrawable001, TestSize.Level1)
{
    auto count = std::make_shared<uint32_t>(std::numeric_limits<uint32_t>::max());
    auto drawable = std::make_shared<DrawableV2::RSRestoreDrawable>(count);
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSCustomSaveDrawable001
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomSaveDrawable001, TestSize.Level1)
{
    auto type = RSPaintFilterCanvas::kCanvas;
    auto status = std::make_shared<RSPaintFilterCanvas::SaveStatus>();
    auto drawable = std::make_shared<DrawableV2::RSCustomSaveDrawable>(status, type);
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSCustomRestoreDrawable001
 * @tc.desc: Test OnDraw
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomRestoreDrawable001, TestSize.Level1)
{
    auto status = std::make_shared<RSPaintFilterCanvas::SaveStatus>();
    auto drawable = std::make_shared<DrawableV2::RSCustomRestoreDrawable>(status);
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(filterCanvas.get(), rect.get());
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RSChildrenDrawableClearDrawableVec001
 * @tc.desc: Test clearDrawableVec on populated RSChildrenDrawable
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSChildrenDrawableClearDrawableVec001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    std::shared_ptr<RSRenderNode> childOne = std::make_shared<RSRenderNode>(2);
    std::shared_ptr<RSRenderNode> childTwo = std::make_shared<RSRenderNode>(3);
    auto drawableOne = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(std::make_shared<RSRenderNode>(10));
    auto drawableTwo = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(std::make_shared<RSRenderNode>(11));
    childOne->renderDrawable_ = drawableOne;
    childTwo->renderDrawable_ = drawableTwo;
    node.AddChild(childOne, -1);
    node.AddChild(childTwo, -1);
    node.GenerateFullChildrenList();

    auto drawable = std::static_pointer_cast<DrawableV2::RSChildrenDrawable>(
        DrawableV2::RSChildrenDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    ASSERT_TRUE(drawable->needSync_);
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);

    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_NE(drawable, nullptr);

    drawable->clearDrawableVec();
    drawable->OnDraw(canvas.get(), rect.get());
    ASSERT_NE(drawable, nullptr);

    drawable->clearDrawableVec();
    drawable->needSync_ = false;
    drawable->OnSync();
    ASSERT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSChildrenDrawableClearDrawableVec002
 * @tc.desc: Test clearDrawableVec on empty RSChildrenDrawable
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSChildrenDrawableClearDrawableVec002, TestSize.Level1)
{
    DrawableV2::RSChildrenDrawable childrenDrawable;
    childrenDrawable.clearDrawableVec();
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    childrenDrawable.OnDraw(canvas.get(), rect.get());
    ASSERT_TRUE(true);
}
/**
 * @tc.name: RSCustomModifierDrawable_OnPurge001
 * @tc.desc: Test OnPurge with empty drawCmdListVec
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomModifierDrawable_OnPurge001, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSCustomModifierDrawable>(ModifierNG::RSModifierType::CONTENT_STYLE);
    drawable->OnPurge();
    EXPECT_TRUE(drawable->drawCmdListVec_.empty());
}

/**
 * @tc.name: RSCustomModifierDrawable_OnPurge002
 * @tc.desc: Test OnPurge with non-empty drawCmdListVec
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomModifierDrawable_OnPurge002, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSCustomModifierDrawable>(ModifierNG::RSModifierType::CONTENT_STYLE);
    auto drawCmdList1 = std::make_shared<RSSimpleDrawCmdList>(1, 1);
    auto drawCmdList2 = std::make_shared<RSSimpleDrawCmdList>(2, 2);
    drawable->drawCmdListVec_.push_back(drawCmdList1);
    drawable->drawCmdListVec_.push_back(drawCmdList2);
    drawable->OnPurge();
    EXPECT_EQ(drawable->drawCmdListVec_.size(), 2u);
}

/**
 * @tc.name: RSCustomModifierDrawable_OnPurge003
 * @tc.desc: Test OnPurge with nullptr entries in drawCmdListVec
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomModifierDrawable_OnPurge003, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSCustomModifierDrawable>(ModifierNG::RSModifierType::CONTENT_STYLE);
    auto drawCmdList = std::make_shared<RSSimpleDrawCmdList>(1, 1);
    drawable->drawCmdListVec_.push_back(drawCmdList);
    drawable->drawCmdListVec_.push_back(nullptr);
    drawable->OnPurge();
    EXPECT_EQ(drawable->drawCmdListVec_.size(), 2u);
}

/**
 * @tc.name: RSBeginBlenderDrawable_PostUpdate001
 * @tc.desc: Test PostUpdate sets enableEDREffect via the NG BRIGHTNESS_BLENDER HdrEnabled tag
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable_PostUpdate001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    node.screenNodeId_ = 42;
    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto brightnessBlender = std::static_pointer_cast<RSNGRenderBrightnessBlender>(ngBlender);
    brightnessBlender->Setter<BrightnessBlenderHdrEnabledRenderTag>(true);
    node.GetMutableRenderProperties().SetNGBlender(ngBlender);
    auto drawable = std::make_shared<DrawableV2::RSBeginBlenderDrawable>();
    drawable->PostUpdate(node);
    EXPECT_TRUE(drawable->enableEDREffect_);
    EXPECT_EQ(drawable->screenNodeId_, 42u);
}

/**
 * @tc.name: RSBeginBlenderDrawable_PostUpdate002
 * @tc.desc: Test PostUpdate with the NG COLORFUL_BRIGHTNESS_BLENDER HdrEnabled tag
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable_PostUpdate002, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    node.screenNodeId_ = 99;
    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto colorfulBlender = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(ngBlender);
    colorfulBlender->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    node.GetMutableRenderProperties().SetNGBlender(ngBlender);
    auto drawable = std::make_shared<DrawableV2::RSBeginBlenderDrawable>();
    drawable->PostUpdate(node);
    EXPECT_TRUE(drawable->enableEDREffect_);
    EXPECT_EQ(drawable->screenNodeId_, 99u);
}

/**
 * @tc.name: RSBeginBlenderDrawable_PostUpdate003
 * @tc.desc: Test PostUpdate without EDR effect
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable_PostUpdate003, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    auto drawable = std::make_shared<DrawableV2::RSBeginBlenderDrawable>();
    drawable->PostUpdate(node);
    EXPECT_FALSE(drawable->enableEDREffect_);
}

/**
 * @tc.name: RSBeginBlenderDrawable_OnDraw001
 * @tc.desc: Test OnDraw returns early when canvas is not PaintFilter
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawable_OnDraw001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    node.GetMutableRenderProperties().SetColorBlendMode(12);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto rect = std::make_shared<Drawing::Rect>();
    drawable->OnDraw(canvas.get(), rect.get());
    EXPECT_NE(canvas, nullptr);
}

/**
 * @tc.name: RSEndBlenderDrawable_OnUpdate001
 * @tc.desc: Test OnUpdate returns false when blendMode is NONE
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSEndBlenderDrawable_OnUpdate001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSEndBlenderDrawable::OnGenerate(node), nullptr);
}

/**
 * @tc.name: RSEndBlenderDrawable_OnUpdate002
 * @tc.desc: Test OnUpdate returns false when blendApplyType is FAST
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSEndBlenderDrawable_OnUpdate002, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    node.GetMutableRenderProperties().SetColorBlendMode(12);
    node.GetMutableRenderProperties().SetColorBlendApplyType(
        static_cast<int>(RSColorBlendApplyType::FAST));
    ASSERT_EQ(DrawableV2::RSEndBlenderDrawable::OnGenerate(node), nullptr);
}

/**
 * @tc.name: RSCustomClipToFrameDrawable_OnGenerate001
 * @tc.desc: Test OnGenerate returns nullptr when modifier is null
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomClipToFrameDrawable_OnGenerate001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSCustomClipToFrameDrawable::OnGenerate(node), nullptr);
}

/**
 * @tc.name: RSCustomClipToFrameDrawable_OnSync001
 * @tc.desc: Test OnSync when needSync_ is false
 * @tc.type: FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSCustomClipToFrameDrawable_OnSync001, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSCustomClipToFrameDrawable>();
    drawable->needSync_ = false;
    drawable->OnSync();
    EXPECT_FALSE(drawable->needSync_);
}

/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate001
 * @tc.desc: Test OnGenerate cache hit when cached drawable holds the same node object;
 *           should return the cached drawable without regeneration.
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate001, TestSize.Level1)
{
    // Unique NodeId to avoid interference with other tests.
    constexpr NodeId testNodeId = 90001;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    auto cachedDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, cachedDrawable);
    }
 
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result.get(), cachedDrawable.get());
    EXPECT_EQ(result->GetId(), testNodeId);
 
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate002
 * @tc.desc: Test OnGenerate cache hit but node address mismatch (stale drawable from old node);
 *           should erase stale cache entry and regenerate (returns nullptr because RS_NODE has no
 *           registered generator in this test binary).
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate002, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90002;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    // Old node object with the same NodeId; its drawable is cached.
    auto oldNode = std::make_shared<RSRenderNode>(testNodeId);
    auto staleDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(oldNode);
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, staleDrawable);
    }
 
    // New node object with the same NodeId but different address.
    auto newNode = std::make_shared<RSRenderNode>(testNodeId);
    ASSERT_NE(newNode.get(), oldNode.get());
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(newNode);
    // RS_NODE generator is not registered in render_service_base test binary, so regeneration
    // returns nullptr. The key assertion is the stale cache entry was erased.
    EXPECT_EQ(result, nullptr);
 
    std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
    EXPECT_EQ(DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.count(testNodeId), 0u);
 
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate003
 * @tc.desc: Test OnGenerate cache hit but NodeType mismatch;
 *           should erase stale cache entry and regenerate.
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate003, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90003;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    // Build a cached drawable whose nodeType_ differs from the incoming node's type.
    // RSRenderNode defaults to RS_NODE (0x0001). We craft the cached drawable's nodeType_
    // to a different value by casting to a mismatched type via direct member mutation.
    auto cachedNode = std::make_shared<RSRenderNode>(testNodeId);
    auto cachedDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(cachedNode);
    cachedDrawable->nodeType_ = RSRenderNodeType::SURFACE_NODE; // mismatch with RS_NODE
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, cachedDrawable);
    }
 
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    ASSERT_NE(node->GetType(), cachedDrawable->GetNodeType());
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    // No RS_NODE generator registered in this test binary, regeneration returns nullptr.
    EXPECT_EQ(result, nullptr);
 
    std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
    EXPECT_EQ(DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.count(testNodeId), 0u);
 
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate004
 * @tc.desc: Test OnGenerate when node is nullptr; should return nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate004, TestSize.Level1)
{
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
    std::shared_ptr<const RSRenderNode> nullNode = nullptr;
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(nullNode);
    EXPECT_EQ(result, nullptr);
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate005
 * @tc.desc: Test OnGenerate when node already has renderDrawable_ set;
 *           should return the existing drawable directly without touching cache.
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate005, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90005;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    auto existingDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    node->renderDrawable_ = existingDrawable;
 
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result.get(), existingDrawable.get());
    // Cache should not be touched (no entry for this nodeId).
    std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
    EXPECT_EQ(DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.count(testNodeId), 0u);
 
    node->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate006
 * @tc.desc: Test OnGenerate successful drawable generation path when GeneratorMap has a registered
 *           generator; should generate, cache, and set node->renderDrawable_.
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate006, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90006;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    // Register a test generator for RS_NODE so the generation path is exercised.
    auto testGenerator = [](std::shared_ptr<const RSRenderNode> node)
        -> DrawableV2::RSRenderNodeDrawableAdapter::Ptr {
        return new ConcreteRSRenderNodeDrawableAdapter(std::move(node));
    };
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap[RSRenderNodeType::RS_NODE] = testGenerator;
 
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    ASSERT_EQ(node->renderDrawable_, nullptr);
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetId(), testNodeId);
    EXPECT_EQ(result->GetNodeType(), RSRenderNodeType::RS_NODE);
    // node->renderDrawable_ should now be set to the generated drawable.
    ASSERT_NE(node->renderDrawable_, nullptr);
    EXPECT_EQ(node->renderDrawable_.get(), result.get());
    // Cache should contain the new drawable entry.
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        EXPECT_EQ(DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.count(testNodeId), 1u);
    }
 
    // Cleanup: remove test generator and clear cache.
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap.erase(RSRenderNodeType::RS_NODE);
    node->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate007
 * @tc.desc: Test OnGenerate when cache entry exists but weak_ptr lock fails (drawable expired);
 *           should erase stale cache entry and regenerate.
 * @tc.type: FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate007, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90007;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    // Create a drawable, put it in cache, then release it so weak_ptr lock fails.
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    {
        auto tempDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, tempDrawable);
    } // tempDrawable destroyed here; cache now holds expired weak_ptr
 
    // Register test generator so regeneration path can succeed.
    auto testGenerator = [](std::shared_ptr<const RSRenderNode> n)
        -> DrawableV2::RSRenderNodeDrawableAdapter::Ptr {
        return new ConcreteRSRenderNodeDrawableAdapter(std::move(n));
    };
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap[RSRenderNodeType::RS_NODE] = testGenerator;
 
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetId(), testNodeId);
    // A new drawable should have been generated and cached.
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        EXPECT_EQ(DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.count(testNodeId), 1u);
    }
 
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap.erase(RSRenderNodeType::RS_NODE);
    node->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate008
 * @tc.desc: Test OnGenerate cache hit with same node address and same NodeType;
 *           verify the cached drawable is returned directly (no regeneration).
 *           This directly validates the node address check added in DTS2026101207391.
 * @tc.type: FUNC
 * @tc.require: DTS2026101207391
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate008, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90008;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    auto cachedDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    ASSERT_EQ(cachedDrawable->GetNodeType(), node->GetType());
    ASSERT_EQ(cachedDrawable->renderNode_.lock().get(), node.get());
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, cachedDrawable);
    }
 
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result.get(), cachedDrawable.get());
    EXPECT_EQ(result->renderNode_.lock().get(), node.get());
 
    node->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate009
 * @tc.desc: Test OnGenerate stale drawable (same NodeId, same NodeType, different node object)
 *           triggers regeneration via registered generator; the new drawable should hold the
 *           new node and the old stale entry should be replaced in cache.
 * @tc.type: FUNC
 * @tc.require: DTS2026101207391
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate009, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90009;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    auto oldNode = std::make_shared<RSRenderNode>(testNodeId);
    auto staleDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(oldNode);
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, staleDrawable);
    }
 
    auto testGenerator = [](std::shared_ptr<const RSRenderNode> n)
        -> DrawableV2::RSRenderNodeDrawableAdapter::Ptr {
        return new ConcreteRSRenderNodeDrawableAdapter(std::move(n));
    };
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap[RSRenderNodeType::RS_NODE] = testGenerator;
 
    auto newNode = std::make_shared<RSRenderNode>(testNodeId);
    ASSERT_NE(newNode.get(), oldNode.get());
    ASSERT_EQ(newNode->GetType(), staleDrawable->GetNodeType());
 
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(newNode);
    ASSERT_NE(result, nullptr);
    EXPECT_NE(result.get(), staleDrawable.get());
    EXPECT_EQ(result->renderNode_.lock().get(), newNode.get());
    ASSERT_NE(newNode->renderDrawable_, nullptr);
    EXPECT_EQ(newNode->renderDrawable_.get(), result.get());
 
    {
        std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
        auto it = DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.find(testNodeId);
        ASSERT_NE(it, DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.end());
        auto cached = it->second.lock();
        ASSERT_NE(cached, nullptr);
        EXPECT_EQ(cached.get(), result.get());
        EXPECT_EQ(cached->renderNode_.lock().get(), newNode.get());
    }
 
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap.erase(RSRenderNodeType::RS_NODE);
    newNode->renderDrawable_ = nullptr;
    oldNode->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate010
 * @tc.desc: Test OnGenerate stale drawable where cached renderNode_ weak_ptr is expired
 *           (old node destroyed) but cache entry still exists; should treat as mismatch
 *           and regenerate.
 * @tc.type: FUNC
 * @tc.require: DTS2026101207391
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate010, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90010;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    {
        auto tempNode = std::make_shared<RSRenderNode>(testNodeId);
        auto tempDrawable = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(tempNode);
        {
            std::lock_guard<std::mutex> lock(DrawableV2::RSRenderNodeDrawableAdapter::cacheMapMutex_);
            DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(testNodeId, tempDrawable);
        }
    } // tempNode and tempDrawable destroyed; cache holds expired weak_ptr for drawable
 
    auto testGenerator = [](std::shared_ptr<const RSRenderNode> n)
        -> DrawableV2::RSRenderNodeDrawableAdapter::Ptr {
        return new ConcreteRSRenderNodeDrawableAdapter(std::move(n));
    };
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap[RSRenderNodeType::RS_NODE] = testGenerator;
 
    auto newNode = std::make_shared<RSRenderNode>(testNodeId);
    auto result = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(newNode);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->renderNode_.lock().get(), newNode.get());
    ASSERT_NE(newNode->renderDrawable_, nullptr);
 
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap.erase(RSRenderNodeType::RS_NODE);
    newNode->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
 
/**
 * @tc.name: RSRenderNodeDrawableAdapterOnGenerate011
 * @tc.desc: Test OnGenerate second call with same node after first generation;
 *           second call should hit cache (same node address) and return same drawable.
 * @tc.type: FUNC
 * @tc.require: DTS2026101207391
 */
HWTEST_F(RSChildrenDrawableTest, RSRenderNodeDrawableAdapterOnGenerate011, TestSize.Level1)
{
    constexpr NodeId testNodeId = 90011;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
 
    auto testGenerator = [](std::shared_ptr<const RSRenderNode> n)
        -> DrawableV2::RSRenderNodeDrawableAdapter::Ptr {
        return new ConcreteRSRenderNodeDrawableAdapter(std::move(n));
    };
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap[RSRenderNodeType::RS_NODE] = testGenerator;
 
    auto node = std::make_shared<RSRenderNode>(testNodeId);
    auto first = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(node->renderDrawable_, nullptr);
 
    // Reset renderDrawable_ to force going through cache lookup path again.
    node->renderDrawable_ = nullptr;
    auto second = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second.get(), first.get());
 
    DrawableV2::RSRenderNodeDrawableAdapter::GeneratorMap.erase(RSRenderNodeType::RS_NODE);
    node->renderDrawable_ = nullptr;
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
/**
 * @tc.name: RSBeginBlenderDrawableAdaptive001
 * @tc.desc: Test the adaptive NG blender channel: OnGenerate needs both blenders, EDR follows
 *           their HdrEnabled tags, and clearing one of them removes the drawable again.
 * @tc.type:FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawableAdaptive001, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    auto dark = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    auto light = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(dark, nullptr);
    ASSERT_NE(light, nullptr);
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(dark)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(light)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);

    auto& properties = node.GetMutableRenderProperties();
    // only one side set: the adaptive channel stays inactive
    properties.SetNGAdaptiveDarkBlender(dark);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    properties.SetNGAdaptiveLightBlender(light);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    ASSERT_TRUE(drawable->GetEnableEDR());
    drawable->OnSync();

    // EDR requires both sides to enable HDR
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(light)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(false);
    auto drawableSdr = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawableSdr, nullptr);
    ASSERT_FALSE(drawableSdr->GetEnableEDR());

    properties.SetNGAdaptiveLightBlender(nullptr);
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);
}

/**
 * @tc.name: RSBeginBlenderDrawableAdaptive002
 * @tc.desc: Test OnDraw with an adaptive blender and a color-picked canvas: the fraction is taken
 *           from the canvas, the interpolated blender is cached and reused for the same fraction.
 * @tc.type:FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawableAdaptive002, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    auto dark = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    auto light = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(dark, nullptr);
    ASSERT_NE(light, nullptr);
    auto& properties = node.GetMutableRenderProperties();
    properties.SetNGAdaptiveDarkBlender(dark);
    properties.SetNGAdaptiveLightBlender(light);

    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();

    Drawing::Canvas canvas;
    std::shared_ptr<RSPaintFilterCanvas> paintFilterCanvas = std::make_shared<RSPaintFilterCanvas>(&canvas);
    RSPaintFilterCanvas::Env env = { RSColor(), nullptr, nullptr, nullptr, true };
    env.fractionColor_ = 0x80;
    paintFilterCanvas->envStack_.push(env);

    Drawing::Rect rect(0, 0, 100, 100);
    drawable->OnDraw(paintFilterCanvas.get(), &rect);
    // same fraction again: the cached blender is reused (early return branch)
    drawable->OnDraw(paintFilterCanvas.get(), &rect);
    // a different fraction rebuilds the cached blender
    paintFilterCanvas->envStack_.top().fractionColor_ = 0x40;
    drawable->OnDraw(paintFilterCanvas.get(), &rect);
    SUCCEED();
}

/**
 * @tc.name: RSBlenderDrawableUtilsAdaptive001
 * @tc.desc: Test MakeAdaptiveBlenderFromNG parameter checks and the adaptive EDR helper branches.
 * @tc.type:FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBlenderDrawableUtilsAdaptive001, TestSize.Level1)
{
    auto dark = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    auto light = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(dark, nullptr);
    ASSERT_NE(light, nullptr);

    // both present: the interpolation path is executed
    RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(dark, light, 0.5f);

    // either side missing: rejected up front
    EXPECT_EQ(RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(nullptr, light, 0.5f), nullptr);
    EXPECT_EQ(RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(dark, nullptr, 0.5f), nullptr);
    EXPECT_EQ(RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(nullptr, nullptr, 0.5f), nullptr);

    // the lerp hdrEnabled_ conjunction: from-dark true with to-light false, then both true
    auto darkHdr = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    auto lightHdr = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(darkHdr, nullptr);
    ASSERT_NE(lightHdr, nullptr);
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(darkHdr)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(darkHdr, lightHdr, 0.5f);
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(lightHdr)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(darkHdr, lightHdr, 0.5f);

    RSProperties properties;
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGAdaptiveBlenderEnableEDR(properties));
    properties.SetNGAdaptiveDarkBlender(dark);
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGAdaptiveBlenderEnableEDR(properties));
    properties.SetNGAdaptiveLightBlender(light);
    EXPECT_FALSE(RSBlenderDrawableUtils::GetNGAdaptiveBlenderEnableEDR(properties));
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(dark)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(light)
        ->Setter<ColorfulBrightnessBlenderHdrEnabledRenderTag>(true);
    EXPECT_TRUE(RSBlenderDrawableUtils::GetNGAdaptiveBlenderEnableEDR(properties));
}

/**
 * @tc.name: RSBeginBlenderDrawableAdaptive003
 * @tc.desc: Cover the remaining adaptive drawable branches: non paint-filter canvas, color picking
 *           not ready, adaptive channel incomplete, and the fraction cache hit/miss.
 * @tc.type:FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawableAdaptive003, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    auto dark = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    auto light = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(dark, nullptr);
    ASSERT_NE(light, nullptr);
    auto& properties = node.GetMutableRenderProperties();
    properties.SetNGAdaptiveDarkBlender(dark);
    properties.SetNGAdaptiveLightBlender(light);

    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();

    Drawing::Rect rect(0, 0, 100, 100);

    // plain canvas: OnDraw returns before touching the adaptive channel
    Drawing::Canvas plainCanvas;
    drawable->OnDraw(&plainCanvas, &rect);

    // paint filter canvas without a color pick result
    std::shared_ptr<RSPaintFilterCanvas> paintFilterCanvas =
        std::make_shared<RSPaintFilterCanvas>(&plainCanvas);
    RSPaintFilterCanvas::Env env = { RSColor(), nullptr, nullptr, nullptr, false };
    paintFilterCanvas->envStack_.push(env);
    drawable->OnDraw(paintFilterCanvas.get(), &rect);

    // only one adaptive blender present: the channel is inactive
    auto savedLight = drawable->adaptiveLightBlender_;
    drawable->adaptiveLightBlender_ = nullptr;
    paintFilterCanvas->envStack_.top().fractionColorReady_ = true;
    paintFilterCanvas->envStack_.top().fractionColor_ = 0x00000080;
    drawable->OnDraw(paintFilterCanvas.get(), &rect);
    drawable->adaptiveLightBlender_ = savedLight;

    // color pick ready: interpolated blender is built (result depends on the runtime effect)
    drawable->OnDraw(paintFilterCanvas.get(), &rect);

    // cover the fraction cache branches deterministically
    drawable->activeBlender_ = std::make_shared<Drawing::Blender>();
    drawable->lastFraction_ = 0.5f;
    drawable->UpdateAdaptiveBlender(0.5f);   // cache hit: early return
    drawable->UpdateAdaptiveBlender(0.25f);  // cache miss: rebuild

    // both adaptive slots cleared: MakeAdaptiveBlenderFromNG returns nullptr and lastFraction_
    // keeps its previous value (the "no blender built" branch)
    drawable->adaptiveLightBlender_ = nullptr;
    drawable->adaptiveDarkBlender_ = nullptr;
    drawable->activeBlender_ = nullptr;
    drawable->lastFraction_ = -2.0f;
    drawable->UpdateAdaptiveBlender(0.75f);
    EXPECT_EQ(drawable->lastFraction_, -2.0f);
    SUCCEED();
}

/**
 * @tc.name: RSBeginBlenderDrawableAdaptive004
 * @tc.desc: Cover the OnUpdate fallback branch: an NG blender of an unmakable type leaves
 *           stagingBlender_ empty, so the blendMode path takes over and the drawable is
 *           generated by the legacy blender instead.
 * @tc.type:FUNC
 */
HWTEST_F(RSChildrenDrawableTest, RSBeginBlenderDrawableAdaptive004, TestSize.Level1)
{
    NodeId id = 1;
    RSRenderNode node(id);
    // an unknow-type NG blender cannot be unpacked (MakeBlenderFromNG returns nullptr)
    node.GetMutableRenderProperties().SetNGBlender(
        RSNGRenderBlenderBase::Create(RSNGEffectType::NONE));
    ASSERT_EQ(DrawableV2::RSBeginBlenderDrawable::OnGenerate(node), nullptr);

    // with a blendMode set, the legacy blender takes over the failed NG unpacking
    node.GetMutableRenderProperties().SetColorBlendMode(12);
    auto drawable = std::static_pointer_cast<DrawableV2::RSBeginBlenderDrawable>(
        DrawableV2::RSBeginBlenderDrawable::OnGenerate(node));
    ASSERT_NE(drawable, nullptr);
    drawable->OnSync();
    EXPECT_NE(drawable->blender_, nullptr);
}
} // namespace OHOS::Rosen
