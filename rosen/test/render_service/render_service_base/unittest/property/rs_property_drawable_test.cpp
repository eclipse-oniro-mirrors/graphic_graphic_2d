/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "property/rs_property_drawable.h"
#include "property/rs_properties.h"
#include "pipeline/rs_render_content.h"
#include "property/rs_property_drawable_frame_geometry.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSPropertyDrawableTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSPropertyDrawableTest::SetUpTestCase() {}
void RSPropertyDrawableTest::TearDownTestCase() {}
void RSPropertyDrawableTest::SetUp() {}
void RSPropertyDrawableTest::TearDown() {}

/**
 * @tc.name: GenerateDirtySlots
 * @tc.desc: test results of GenerateDirtySlots
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSPropertyDrawableTest, GenerateDirtySlots, TestSize.Level1)
{
    RSProperties properties;
    std::bitset<static_cast<int>(RSModifierType::MAX_RS_MODIFIER_TYPE)> dirtyTypes;
    dirtyTypes.set(16); //for test
    dirtyTypes.set(3); //for test
    dirtyTypes.set(4); //for test
    dirtyTypes.set(5); //for test
    dirtyTypes.set(6); //for test
    (void)RSPropertyDrawable::GenerateDirtySlots(properties, dirtyTypes);
    EXPECT_TRUE(properties.border_ == nullptr);

    dirtyTypes.set(1); //for test
    (void)RSPropertyDrawable::GenerateDirtySlots(properties, dirtyTypes);
    EXPECT_TRUE(properties.border_ == nullptr);

    Vector4f stretchSize(1e-6f, 1e-6f, 1e-6f, 1.0); //for test
    properties.SetPixelStretch(stretchSize);
    Vector4f width = { 1.f, 1.f, 1.f, 1.f }; //for test
    properties.SetBorderWidth(width);
    Vector4f radius = { 1.f, 1.f, 1.f, 1.f }; //for test
    properties.SetOutlineRadius(radius);
    (void)RSPropertyDrawable::GenerateDirtySlots(properties, dirtyTypes);
    EXPECT_TRUE(properties.border_ != nullptr);

    dirtyTypes.set(17); //for test
    (void)RSPropertyDrawable::GenerateDirtySlots(properties, dirtyTypes);
    EXPECT_TRUE(properties.border_ != nullptr);

    properties.border_ = nullptr;
    properties.outline_ = nullptr;
    (void)RSPropertyDrawable::GenerateDirtySlots(properties, dirtyTypes);

    dirtyTypes.set(8); //for test
    dirtyTypes.set(12); //for test
    (void)RSPropertyDrawable::GenerateDirtySlots(properties, dirtyTypes);
}

/**
 * @tc.name: UpdateDrawableVec
 * @tc.desc: test results of UpdateDrawableVec
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSPropertyDrawableTest, UpdateDrawableVec, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    std::unordered_set<RSPropertyDrawableSlot> dirtySlots;
    RSPropertyDrawable::UpdateDrawableVec(content, drawableVec, dirtySlots);
    EXPECT_EQ(dirtySlots.empty(), true);

    std::vector<RSPropertyDrawableSlot> slots = {
        RSPropertyDrawableSlot::INVALID,
        RSPropertyDrawableSlot::SAVE_ALL,
        RSPropertyDrawableSlot::BOUNDS_MATRIX,
        RSPropertyDrawableSlot::ALPHA,
        RSPropertyDrawableSlot::MASK,
        RSPropertyDrawableSlot::TRANSITION,
        RSPropertyDrawableSlot::ENV_FOREGROUND_COLOR,
        RSPropertyDrawableSlot::SHADOW,
        RSPropertyDrawableSlot::OUTLINE,
        RSPropertyDrawableSlot::BG_SAVE_BOUNDS,
        RSPropertyDrawableSlot::CLIP_TO_BOUNDS,
        RSPropertyDrawableSlot::BLEND_MODE,
        RSPropertyDrawableSlot::BACKGROUND_COLOR,
        RSPropertyDrawableSlot::BACKGROUND_SHADER,
        RSPropertyDrawableSlot::BACKGROUND_IMAGE,
        RSPropertyDrawableSlot::BACKGROUND_FILTER,
        RSPropertyDrawableSlot::USE_EFFECT,
        RSPropertyDrawableSlot::BACKGROUND_STYLE,
        RSPropertyDrawableSlot::DYNAMIC_LIGHT_UP,
        RSPropertyDrawableSlot::ENV_FOREGROUND_COLOR_STRATEGY,
        RSPropertyDrawableSlot::BG_RESTORE_BOUNDS
    }; //for test
    for (const auto& slot : slots) {
        dirtySlots.emplace(slot);
    }
    RSPropertyDrawable::UpdateDrawableVec(content, drawableVec, dirtySlots);
    EXPECT_EQ(dirtySlots.empty(), false);

    dirtySlots.clear();
    dirtySlots.emplace(RSPropertyDrawableSlot::BG_RESTORE_BOUNDS);
    RSPropertyDrawable::UpdateDrawableVec(content, drawableVec, dirtySlots);
    EXPECT_EQ(dirtySlots.empty(), false);

    dirtySlots.emplace(RSPropertyDrawableSlot::CLIP_TO_BOUNDS);
    RSPropertyDrawable::UpdateDrawableVec(content, drawableVec, dirtySlots);
    EXPECT_EQ(dirtySlots.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore001
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore001, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 1;
    auto& properties = content.GetMutableRenderProperties();
    properties.SetClipToBounds(true);
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    status = 55;
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore002
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore002, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 1;
    auto& properties = content.GetMutableRenderProperties();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    status = 55;
    properties.clipToBounds_ = true;
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    RRect rect;
    properties.clipRRect_ = rect;
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    properties.clipPath_ = std::make_shared<RSPath>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    properties.colorBlendMode_ = 1;
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore003
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore003, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 1;
    auto& properties = content.GetMutableRenderProperties();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    status = 55;
    properties.clipToFrame_ = true;
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore004
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore004, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 1;
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::BG_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::FG_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);

    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::CONTENT_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore005
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore005, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 55;
    auto& properties = content.GetMutableRenderProperties();
    properties.clipToBounds_ = true;
    RRect rect;
    properties.clipRRect_ = rect;
    properties.clipPath_ = std::make_shared<RSPath>();
    properties.colorBlendMode_ = 1;
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore006
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore006, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 55;
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::BG_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::FG_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore007
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore007, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 55;
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::FG_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::CONTENT_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore008
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore008, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 55;
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::FG_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}

/**
 * @tc.name: UpdateSaveRestore009
 * @tc.desc: test results of UpdateSaveRestore
 * @tc.type: FUNC
 * @tc.require: issueI9RBVH
 */
HWTEST_F(RSPropertyDrawableTest, UpdateSaveRestore009, TestSize.Level1)
{
    RSRenderContent content;
    RSPropertyDrawable::DrawableVec drawableVec;
    uint8_t status = 24;
    drawableVec[static_cast<size_t>(RSPropertyDrawableSlot::CONTENT_PROPERTIES_BEGIN)] =
        std::make_unique<RSFrameGeometryDrawable>();
    RSPropertyDrawable::UpdateSaveRestore(content, drawableVec, status);
    EXPECT_EQ(drawableVec.empty(), false);
}
} // namespace Rosen
} // namespace OHOS