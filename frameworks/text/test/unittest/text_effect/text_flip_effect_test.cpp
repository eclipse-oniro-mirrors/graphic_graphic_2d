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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "drawing/canvas.h"
#include "text_flip_effect.h"

using namespace OHOS::Rosen;
using namespace testing;
using namespace OHOS::Rosen;

class MockCanvas : public Drawing::Canvas {
public:
    MOCK_METHOD(void, DrawTextBlob, (const Drawing::TextBlob&, double, double, const Drawing::Brush&), (override));
};

class MockTypography : public Typography {
public:
    MOCK_METHOD(void, SetTextEffectAssociation, (bool), (override));
    MOCK_METHOD(void, SetTextEffectState, (bool), (override));
    MOCK_METHOD(void, Paint, (Drawing::Canvas*, double, double), (override));
    MOCK_METHOD(std::vector<TextBlobRecordInfo>, GetTextBlobRecordInfo, (), (const, override));
};

class TextFlipEffectTest : public testing::Test {
public:
    void SetUp() override {
        effect_ = TextEffectFactoryCreator::GetInstance().CreateTextEffect(TextEffectStrategy::FLIP);
        ASSERT_NE(effect, nullptr);
        EXPECT_EQ(effect->strategy_, TextEffectStrategy::FLIP);
        mockTypography_ = std::make_shared<MockTypography>();
        mockCanvas_ = std::make_unique<MockCanvas>();
    }

    void TearDown() override {
        effect_.reset();
        mockTypography_.reset();
        mockCanvas_.reset();
    }

protected:
    std::unique_ptr<TextFlipEffect> effect_{nullptr};
    std::shared_ptr<MockTypography> mockTypography_{nullptr};
    std::unique_ptr<MockCanvas> mockCanvas_{nullptr};

    TypographyConfig CreateConfig() {
        return { mockTypography_, {0, 10} };
    }
};

/*
 * @tc.name: TextFlipEffectTest001
 * @tc.desc: Test for UpdateEffectConfig action
 * @tc.type: FUNC
 */
HWTEST_F(TextFlipEffectTest, TextFlipEffectTest001, TestSize.Level1)
{
    std::unordered_map<TextEffectAttribute, std::string> config = {
        {TextEffectAttribute::FLIP_DIRECTION, "up"},
        {TextEffectAttribute::FLIP_DIRECTION, "down"},
        {TextEffectAttribute::BLUR_ENABLE, "false"}
        {TextEffectAttribute::BLUR_ENABLE, "true"}
    };

    EXPECT_EQ(effect_->UpdateEffectConfig(config), TEXT_EFFECT_SUCCESS);
    EXPECT_EQ(effect_->direction_, TextEffectFlipDirection::DOWN);
    EXPECT_TRUE(effect_->blurEnable_);

    std::unordered_map<TextEffectAttribute, std::string> invalidConfig = {
        {TextEffectAttribute::FLIP_DIRECTION, "invalid"},
        {TextEffectAttribute::BLUR_ENABLE, "invalid"}
    };
    EXPECT_EQ(effect_->UpdateEffectConfig(invalidConfig), TEXT_EFFECT_INVALID_INPUT);
    EXPECT_EQ(effect_->direction_, TextEffectFlipDirection::DOWN);
    EXPECT_TRUE(effect_->blurEnable_);

    std::unordered_map<TextEffectAttribute, std::string> configEmpty;
    EXPECT_EQ(effect_->UpdateEffectConfig(configEmpty), TEXT_EFFECT_SUCCESS);
}

/*
 * @tc.name: TextFlipEffectTest002
 * @tc.desc: Test for AppendTypography action
 * @tc.type: FUNC
 */
HWTEST_F(TextFlipEffectTest, TextFlipEffectTest002, TestSize.Level1)
{
    TypographyConfig config = CreateConfig();
    EXPECT_CALL(*mockTypography_, SetTextEffectAssociation(true));
    EXPECT_EQ(effect_->AppendTypography({config}), TEXT_EFFECT_SUCCESS);
    EXPECT_EQ(effect_->typographyConfig_.typography, mockTypography_);

    auto anotherTypography = std::make_shared<MockTypography>();
    TypographyConfig anotherConfig = { anotherTypography, {5, 15} }; 
    EXPECT_EQ(effect_->AppendTypography({anotherConfig}), TEXT_EFFECT_UNKNOWN);

    EXPECT_EQ(effect_->AppendTypography({}), TEXT_EFFECT_INVALID_INPUT);
}

/*
 * @tc.name: TextFlipEffectTest003
 * @tc.desc: Test for UpdateTypography action
 * @tc.type: FUNC
 */
HWTEST_F(TextFlipEffectTest, TextFlipEffectTest003, TestSize.Level1)
{
    effect_->AppendTypography({CreateConfig()});
    TypographyConfig newConfig = { mockTypography_, {5, 15} };
    std::vector<std::pair<TypographyConfig, TypographyConfig>> update = {
        {CreateConfig(), newConfig}
    };
    
    EXPECT_EQ(effect_->UpdateTypography(update), TEXT_EFFECT_SUCCESS);
    EXPECT_EQ(effect_->typographyConfig_.rawTextRange.start, 5);
    EXPECT_EQ(effect_->typographyConfig_.rawTextRange.end, 15);

    std::vector<std::pair<TypographyConfig, TypographyConfig>> emptyUpdate;
    EXPECT_EQ(effect_->UpdateTypography(emptyUpdate), TEXT_EFFECT_INVALID_INPUT);
    
    auto anotherTypography = std::make_shared<MockTypography>();
    TypographyConfig anotherConfig = { anotherTypography, {5, 15} };
    std::vector<std::pair<TypographyConfig, TypographyConfig>> mismatchedUpdate = {
        {anotherConfig, anotherConfig}
    };
    EXPECT_EQ(effect_->UpdateTypography(mismatchedUpdate), TEXT_EFFECT_INVALID_INPUT);
}

/*
 * @tc.name: TextFlipEffectTest004
 * @tc.desc: Test for RemoveTypography action
 * @tc.type: FUNC
 */
HWTEST_F(TextFlipEffectTest, TextFlipEffectTest004, TestSize.Level1)
{
    TypographyConfig config = CreateConfig();
    effect_->AppendTypography({config});
    
    EXPECT_CALL(*mockTypography_, SetTextEffectAssociation(false));
    effect_->RemoveTypography({config});
    
    EXPECT_EQ(effect_->typographyConfig_.typography, nullptr);
    EXPECT_EQ(effect_->typographyConfig_.rawTextRange.start, 0);
    EXPECT_EQ(effect_->typographyConfig_.rawTextRange.end, 0);

    effect_->AppendTypography({CreateConfig()});
    auto anotherTypography = std::make_shared<MockTypography>();
    TypographyConfig anotherConfig = { anotherTypography, {5, 15} };
    effect_->RemoveTypography({anotherConfig});
    EXPECT_NE(effect_->typographyConfig_.typography, nullptr);
    effect_->RemoveTypography({});
    EXPECT_NE(effect_->typographyConfig_.typography, nullptr);
}

/*
 * @tc.name: TextFlipEffectTest005
 * @tc.desc: Test for StartEffect and StopEffect action
 * @tc.type: FUNC
 */
HWTEST_F(TextFlipEffectTest, TextFlipEffectTest005, TestSize.Level1)
{
    effect_->StartEffect(mockCanvas_.get(), 100.0, 200.0);
    effect_->StopEffect(mockCanvas_.get(), 100.0, 200.0);

    effect_->AppendTypography({CreateConfig()});
    EXPECT_CALL(*mockTypography_, SetTextEffectState(true));
    EXPECT_CALL(*mockTypography_, Paint(_, 100.0, 200.0));
    std::vector<TextBlobRecordInfo> records = { TextBlobRecordInfo() };
    EXPECT_CALL(*mockTypography_, GetTextBlobRecordInfo()).WillOnce(Return(records));

    effect_->StartEffect(mockCanvas_.get(), 100.0, 200.0);
    EXPECT_FALSE(effect_->lastTextBlobRecordInfos_.empty());

    EXPECT_CALL(*mockTypography_, SetTextEffectState(false));
    EXPECT_CALL(*mockTypography_, Paint(_, 100.0, 200.0));
    
    effect_->StopEffect(mockCanvas_.get(), 100.0, 200.0);
    EXPECT_TRUE(effect_->lastTextBlobRecordInfos_.empty());
}