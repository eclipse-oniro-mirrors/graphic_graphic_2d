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

#include "gtest/gtest.h"
#include "parcel.h"

#include "common/rs_vector3.h"
#include "effect/rs_render_blender_base.h"
#include "transaction/rs_marshalling_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRenderBlenderBaseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderBlenderBaseTest::SetUpTestCase() {}
void RSRenderBlenderBaseTest::TearDownTestCase() {}
void RSRenderBlenderBaseTest::SetUp() {}
void RSRenderBlenderBaseTest::TearDown() {}

/**
 * @tc.name: RSNGRenderBlenderBaseCreate001
 * @tc.desc: Test RSNGRenderBlenderBase::Create for all registered blender types and an
 *           unregistered type (returns nullptr).
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderBlenderBaseTest, RSNGRenderBlenderBaseCreate001, TestSize.Level1)
{
    EXPECT_NE(RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER), nullptr);
    EXPECT_NE(RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER), nullptr);
    EXPECT_NE(RSNGRenderBlenderBase::Create(RSNGEffectType::HDR_DARKEN_BLENDER), nullptr);

    // NONE has no creator registered
    EXPECT_EQ(RSNGRenderBlenderBase::Create(RSNGEffectType::NONE), nullptr);
}

/**
 * @tc.name: MarshallingAndUnmarshalling001
 * @tc.desc: Test the Marshalling and Unmarshalling methods can serialize and deserialize a
 *           single blender and a blender chain correctly, keeping types and tag values.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderBlenderBaseTest, MarshallingAndUnmarshalling001, TestSize.Level1)
{
    Parcel parcel;
    auto blender1 = std::make_shared<RSNGRenderHdrDarkenBlender>();
    blender1->Setter<HdrDarkenBlenderHdrBrightnessRatioRenderTag>(2.0f);
    blender1->Setter<HdrDarkenBlenderGrayscaleFactorRenderTag>(Vector3f(0.299f, 0.587f, 0.114f));
    auto blender2 = RSNGRenderBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER);
    blender1->nextEffect_ = blender2;

    EXPECT_TRUE(blender1->Marshalling(parcel));

    std::shared_ptr<RSNGRenderBlenderBase> outBlender;
    EXPECT_TRUE(RSNGRenderBlenderBase::Unmarshalling(parcel, outBlender));
    ASSERT_NE(outBlender, nullptr);
    EXPECT_EQ(outBlender->GetType(), RSNGEffectType::HDR_DARKEN_BLENDER);
    EXPECT_EQ(outBlender->GetEffectCount(), blender1->GetEffectCount());
    auto outHdrDarken = std::static_pointer_cast<RSNGRenderHdrDarkenBlender>(outBlender);
    EXPECT_FLOAT_EQ(outHdrDarken->Getter<HdrDarkenBlenderHdrBrightnessRatioRenderTag>()->Get(), 2.0f);
    EXPECT_EQ(outHdrDarken->Getter<HdrDarkenBlenderGrayscaleFactorRenderTag>()->Get(),
        Vector3f(0.299f, 0.587f, 0.114f));
    ASSERT_NE(outBlender->nextEffect_, nullptr);
    EXPECT_EQ(outBlender->nextEffect_->GetType(), RSNGEffectType::BRIGHTNESS_BLENDER);

    // Test Unmarshalling empty parcel
    Parcel emptyParcel;
    std::shared_ptr<RSNGRenderBlenderBase> emptyBlender;
    EXPECT_FALSE(RSNGRenderBlenderBase::Unmarshalling(emptyParcel, emptyBlender));

    // Test Unmarshalling NONE type: no creator registered, Create returns nullptr
    Parcel noneParcel;
    RSMarshallingHelper::Marshalling(noneParcel, static_cast<RSNGEffectTypeUnderlying>(RSNGEffectType::NONE));
    std::shared_ptr<RSNGRenderBlenderBase> noneBlender;
    EXPECT_FALSE(RSNGRenderBlenderBase::Unmarshalling(noneParcel, noneBlender));
    EXPECT_EQ(noneBlender, nullptr);

    // Test Unmarshalling END_OF_CHAIN type: succeeds with a null result
    Parcel endOfChainParcel;
    RSMarshallingHelper::Marshalling(endOfChainParcel, END_OF_CHAIN);
    std::shared_ptr<RSNGRenderBlenderBase> endOfChainBlender;
    EXPECT_TRUE(RSNGRenderBlenderBase::Unmarshalling(endOfChainParcel, endOfChainBlender));
    EXPECT_EQ(endOfChainBlender, nullptr);
}

/**
 * @tc.name: MarshallingAndUnmarshalling002
 * @tc.desc: Test the Marshalling and Unmarshalling methods can handle a blender chain that
 *           exceeds the RSNGRenderBlenderBase::EFFECT_COUNT_LIMIT.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderBlenderBaseTest, MarshallingAndUnmarshalling002, TestSize.Level1)
{
    // Test Marshalling long blender chain
    auto longBlender = std::make_shared<RSNGRenderHdrDarkenBlender>();
    std::shared_ptr<RSNGRenderBlenderBase> current = longBlender;
    for (size_t i = 1; i < RSNGRenderBlenderBase::EFFECT_COUNT_LIMIT; ++i) {
        auto next = std::make_shared<RSNGRenderHdrDarkenBlender>();
        current->nextEffect_ = next;
        current = next;
    }
    Parcel parcel;
    EXPECT_FALSE(longBlender->Marshalling(parcel));

    // Test Unmarshalling with a parcel that has exceeded the limit
    Parcel parcel2;
    auto blender = std::make_shared<RSNGRenderHdrDarkenBlender>();
    EXPECT_TRUE(blender->Marshalling(parcel2));
    RSNGEffectTypeUnderlying val = 0;
    EXPECT_TRUE(RSMarshallingHelper::Unmarshalling(parcel2, val));
    current = blender;
    for (size_t i = 1; i < RSNGRenderBlenderBase::EFFECT_COUNT_LIMIT; ++i) {
        auto nextBlender = std::make_shared<RSNGRenderHdrDarkenBlender>();
        current->nextEffect_ = nextBlender;
        current = nextBlender;
    }
    EXPECT_FALSE(blender->Marshalling(parcel2));
    std::shared_ptr<RSNGRenderBlenderBase> outBlender = nullptr;
    EXPECT_FALSE(RSNGRenderBlenderBase::Unmarshalling(parcel2, outBlender));
    EXPECT_EQ(outBlender, nullptr);
}

/**
 * @tc.name: MarshallingAndUnmarshalling003
 * @tc.desc: Test the Unmarshalling method handles a valid type but fails when the parcel
 *           data is insufficient (OnUnmarshalling fails).
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderBlenderBaseTest, MarshallingAndUnmarshalling003, TestSize.Level1)
{
    Parcel invalidDataParcel;
    RSMarshallingHelper::Marshalling(invalidDataParcel,
        static_cast<RSNGEffectTypeUnderlying>(RSNGEffectType::HDR_DARKEN_BLENDER));
    std::shared_ptr<RSNGRenderBlenderBase> invalidDataBlender;
    EXPECT_FALSE(RSNGRenderBlenderBase::Unmarshalling(invalidDataParcel, invalidDataBlender));
}

/**
 * @tc.name: MarshallingNullptr001
 * @tc.desc: Test RSMarshallingHelper::Marshalling with a null blender pointer: it writes
 *           END_OF_CHAIN and Unmarshalling reads it back as a null result.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderBlenderBaseTest, MarshallingNullptr001, TestSize.Level1)
{
    Parcel parcel;
    std::shared_ptr<RSNGRenderBlenderBase> nullBlender;
    EXPECT_TRUE(RSMarshallingHelper::Marshalling(parcel, nullBlender));

    std::shared_ptr<RSNGRenderBlenderBase> outBlender;
    EXPECT_TRUE(RSMarshallingHelper::Unmarshalling(parcel, outBlender));
    EXPECT_EQ(outBlender, nullptr);
}

/**
 * @tc.name: UnmarshallingEffectCountLimit001
 * @tc.desc: Test the effect-count limit branch of RSNGRenderBlenderBase::Unmarshalling: a
 *           parcel holding EFFECT_COUNT_LIMIT blender payloads without END_OF_CHAIN fails
 *           after the loop is exhausted. The payload is derived from marshalled chains, so
 *           the test does not depend on the concrete wire format of the tags.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderBlenderBaseTest, UnmarshallingEffectCountLimit001, TestSize.Level1)
{
    // single blender payload (without the trailing END_OF_CHAIN):
    // len(chain of 2) - len(chain of 1) == len(one blender payload)
    auto head = std::make_shared<RSNGRenderHdrDarkenBlender>();
    Parcel single;
    ASSERT_TRUE(head->Marshalling(single));
    head->nextEffect_ = std::make_shared<RSNGRenderHdrDarkenBlender>();
    Parcel chained;
    ASSERT_TRUE(head->Marshalling(chained));
    const size_t payloadLen = chained.GetWritePosition() - single.GetWritePosition();
    ASSERT_GT(payloadLen, 0u);
    ASSERT_LT(payloadLen, single.GetWritePosition());

    Parcel parcel;
    const uint8_t* payload = single.ReadUnpadBuffer(payloadLen);
    ASSERT_NE(payload, nullptr);
    for (size_t i = 0; i < RSNGRenderBlenderBase::EFFECT_COUNT_LIMIT; ++i) {
        ASSERT_TRUE(parcel.WriteUnpadBuffer(payload, payloadLen));
    }
    std::shared_ptr<RSNGRenderBlenderBase> outBlender;
    EXPECT_FALSE(RSNGRenderBlenderBase::Unmarshalling(parcel, outBlender));
    EXPECT_EQ(outBlender, nullptr);
}
} // namespace OHOS::Rosen
