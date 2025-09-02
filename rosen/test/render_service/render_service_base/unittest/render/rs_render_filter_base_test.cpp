
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
#include "gtest/gtest.h"
#include "ge_visual_effect_impl.h"
#include "effect/rs_render_filter_base.h"
#include "pipeline/rs_render_node.h"
#include "render/rs_render_filter_base.h"
#include "transaction/rs_marshalling_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRenderFilterBaseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderFilterBaseTest::SetUpTestCase() {}
void RSRenderFilterBaseTest::TearDownTestCase() {}
void RSRenderFilterBaseTest::SetUp() {}
void RSRenderFilterBaseTest::TearDown() {}

/**
 * @tc.name: GenerateGEVisualEffect
 * @tc.desc: Test the GenerateGEVisualEffect method
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, GenerateGEVisualEffect, TestSize.Level1)
{
    std::shared_ptr<RSNGRenderFilterBase> filterNull = nullptr;
    RSUIFilterHelper::GenerateGEVisualEffect(filterNull);
    std::shared_ptr<RSNGRenderFilterBase> filter = std::make_shared<RSNGRenderBlurFilter>();
    RSUIFilterHelper::GenerateGEVisualEffect(filter);
    EXPECT_NE(filter->geFilter_, nullptr);
}

/**
 * @tc.name: CreateAndGetType001
 * @tc.desc: Test the factory method can create filter with correct type
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, CreateAndGetType001, TestSize.Level1)
{
    // normal filter types
    auto filterTypes = {
        RSNGEffectType::BLUR,
        RSNGEffectType::EDGE_LIGHT,
        RSNGEffectType::SOUND_WAVE,
        RSNGEffectType::DISPERSION,
        RSNGEffectType::EDGE_LIGHT
    };
    for (const auto& type : filterTypes) {
        auto filter = RSNGRenderFilterBase::Create(type);
        ASSERT_NE(filter, nullptr);
        EXPECT_EQ(filter->GetType(), type);
    }

    // invalid filter type
    auto invalidFilter = RSNGRenderFilterBase::Create(RSNGEffectType::INVALID);
    EXPECT_EQ(invalidFilter, nullptr);
    auto noneFilter = RSNGRenderFilterBase::Create(RSNGEffectType::NONE);
    EXPECT_EQ(noneFilter, nullptr);
}

/**
 * @tc.name: UpdateCacheData
 * @tc.desc: Test the UpdateCacheData method
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, UpdateCacheData, TestSize.Level1)
{
    auto src = std::make_shared<Drawing::GEVisualEffect>("KAWASE_BLUR");
    auto dest = std::make_shared<Drawing::GEVisualEffect>("KAWASE_BLUR");
    auto other = std::make_shared<Drawing::GEVisualEffect>("MESA_BLUR");
    RSUIFilterHelper::UpdateCacheData(src, dest);
    EXPECT_EQ(dest->GetImpl()->GetCache(), nullptr);
    src->GetImpl()->SetCache(std::make_shared<std::any>(std::make_any<float>(1.0)));
    std::shared_ptr<Drawing::GEVisualEffect> null = nullptr;
    RSUIFilterHelper::UpdateCacheData(null, null);
    EXPECT_EQ(null, nullptr);
    RSUIFilterHelper::UpdateCacheData(null, dest);
    RSUIFilterHelper::UpdateCacheData(src, null);
    EXPECT_EQ(null, nullptr);
    ASSERT_NE(src->GetImpl()->GetFilterType(), other->GetImpl()->GetFilterType());
    RSUIFilterHelper::UpdateCacheData(src, other);
    EXPECT_EQ(other->GetImpl()->GetCache(), nullptr);
    RSUIFilterHelper::UpdateCacheData(src, dest);
    auto cachePtr = dest->GetImpl()->GetCache();
    auto cache = std::any_cast<float>(*cachePtr);
    EXPECT_EQ(cache, 1.0);
}

/**
 * @tc.name: GetEffectCount001
 * @tc.desc: 1. Test the behavior of Append method, including appending self, appending valid filters,
 *           handling null filters, and ensuring filters already in the chain are not appended again
 *           2. Test GetEffectCount method to verify the number of filters in the chain
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, GetEffectCount001, TestSize.Level1)
{
    // Test single filter
    auto filter1 = RSNGRenderFilterBase::Create(RSNGEffectType::BLUR);
    EXPECT_EQ(filter1->GetEffectCount(), 1u);

    // Test append filter: BLUR -> EDGE_LIGHT
    auto filter2 = RSNGRenderFilterBase::Create(RSNGEffectType::EDGE_LIGHT);
    filter1->nextEffect_ = filter2;
    EXPECT_EQ(filter1->nextEffect_, filter2);
    EXPECT_EQ(filter1->GetEffectCount(), 2u);

    // Test append nullptr
    filter2->nextEffect_ = nullptr;
    EXPECT_EQ(filter1->GetEffectCount(), 2u);

    // Test append filter: BLUR -> EDGE_LIGHT -> SOUND_WAVE
    auto filter3 = RSNGRenderFilterBase::Create(RSNGEffectType::SOUND_WAVE);
    filter2->nextEffect_ = filter3;
    EXPECT_EQ(filter1->GetEffectCount(), 3u);

    // Test set next filter at middle
    auto filter4 = RSNGRenderFilterBase::Create(RSNGEffectType::DISPERSION);
    filter2->nextEffect_ = filter4;
    EXPECT_EQ(filter2->nextEffect_, filter4);
    EXPECT_EQ(filter3->nextEffect_, nullptr);
    EXPECT_EQ(filter1->GetEffectCount(), 3u);
}

/**
 * @tc.name: Dump001
 * @tc.desc: Test the Dump method outputs correct filter type information
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, Dump001, TestSize.Level1)
{
    std::shared_ptr<RSNGRenderFilterBase> filter = std::make_shared<RSNGRenderBlurFilter>();
    std::string out;
    filter->Dump(out);
    EXPECT_NE(out.find("Blur"), std::string::npos);

    std::shared_ptr<RSNGRenderFilterBase> nextFilter = std::make_shared<RSNGRenderEdgeLightFilter>();
    filter->nextEffect_ = nextFilter;
    filter->Dump(out);
    EXPECT_NE(out.find("EdgeLight"), std::string::npos);
}

/**
 * @tc.name: TemplateContains001
 * @tc.desc: querify the RSNGRenderFilterTemplate's Contains template interface
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, TemplateContains001, TestSize.Level1)
{
    auto filter = std::make_shared<RSNGRenderBlurFilter>();
    EXPECT_TRUE(filter->Contains<BlurRadiusXRenderTag>());
    EXPECT_FALSE(filter->Contains<EdgeLightColorRenderTag>());
}

/**
 * @tc.name: TemplateGetterSetter001
 * @tc.desc: querify the RSNGRenderFilterTemplate's Getter and Setter template interfaces
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, TemplateGetterSetter001, TestSize.Level1)
{
    auto filter = std::make_shared<RSNGRenderBlurFilter>();
    using TargetTag = BlurRadiusXRenderTag;
    constexpr float value = 1.23f;
    filter->Setter<TargetTag>(value);
    auto val = filter->Getter<TargetTag>();
    ASSERT_NE(val, nullptr);
    EXPECT_FLOAT_EQ(val->Get(), value);
}

/**
 * @tc.name: MarshallingAndUnmarshalling001
 * @tc.desc: Test the Marshalling and Unmarshalling methods can
 *           serialize and deserialize a single filter correctly
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, MarshallingAndUnmarshalling001, TestSize.Level1)
{
    // Test Marshalling and Unmarshalling of a single filter and chained filters
    Parcel parcel;
    auto filter1 = std::make_shared<RSNGRenderBlurFilter>();
    auto filter2 = RSNGRenderFilterBase::Create(RSNGEffectType::EDGE_LIGHT);
    filter1->nextEffect_ = filter2;
    std::shared_ptr<RSNGRenderFilterBase> outFilter;
    auto testFunc = [&parcel](const auto& inFilter, auto& outFilter) {
        EXPECT_NE(inFilter, nullptr);
        bool ret = inFilter->Marshalling(parcel);
        EXPECT_TRUE(ret);
        ret = RSNGRenderFilterBase::Unmarshalling(parcel, outFilter);
        EXPECT_TRUE(ret);
        EXPECT_NE(outFilter, nullptr);
        EXPECT_EQ(outFilter->GetType(), inFilter->GetType());
        EXPECT_EQ(outFilter->GetEffectCount(), inFilter->GetEffectCount());
        if (inFilter->nextEffect_ != nullptr) {
            ASSERT_NE(outFilter->nextEffect_, nullptr);
            EXPECT_EQ(outFilter->nextEffect_->GetType(), inFilter->nextEffect_->GetType());
        } else {
            EXPECT_EQ(outFilter->nextEffect_, nullptr);
        }
    };
    testFunc(filter1, outFilter);
    testFunc(filter2, outFilter);

    // Test Unmarshalling empty parcel
    Parcel emptyParcel;
    std::shared_ptr<RSNGRenderFilterBase> emptyFilter;
    bool ret = RSNGRenderFilterBase::Unmarshalling(emptyParcel, emptyFilter);

    EXPECT_FALSE(ret);
    // Test Unmarshalling none type
    Parcel noneParcel;
    RSMarshallingHelper::Marshalling(noneParcel, static_cast<RSUIFilterTypeUnderlying>(RSNGEffectType::NONE));
    std::shared_ptr<RSNGRenderFilterBase> noneFilter;
    ret = RSNGRenderFilterBase::Unmarshalling(noneParcel, noneFilter);
    EXPECT_FALSE(ret);
    EXPECT_EQ(noneFilter, nullptr); // NONE should return nullptr

    // Test Unmarshalling END_OF_CHAIN type
    Parcel endOfChainParcel;
    RSMarshallingHelper::Marshalling(endOfChainParcel, END_OF_CHAIN);
    std::shared_ptr<RSNGRenderFilterBase> endOfChainFilter;
    ret = RSNGRenderFilterBase::Unmarshalling(endOfChainParcel, endOfChainFilter);
    EXPECT_TRUE(ret);
    EXPECT_EQ(endOfChainFilter, nullptr); // END_OF_CHAIN should return nullptr
}

/**
 * @tc.name: MarshallingAndUnmarshalling002
 * @tc.desc: Test the Marshalling and Unmarshalling methods can handle
 *           a filter chain that exceeds the RSNGRenderFilterBase::EFFECT_COUNT_LIMIT
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, MarshallingAndUnmarshalling002, TestSize.Level1)
{
    // Test Marshalling long filter chain
    auto longFilter = std::make_shared<RSNGRenderBlurFilter>();
    std::shared_ptr<RSNGRenderFilterBase> current = longFilter;
    for (size_t i = 1; i < RSNGRenderFilterBase::EFFECT_COUNT_LIMIT; ++i) {
        auto next = std::make_shared<RSNGRenderBlurFilter>();
        current->nextEffect_ = next;
        current = next;
    }
    Parcel parcel;
    auto ret = longFilter->Marshalling(parcel);
    EXPECT_FALSE(ret);

    // Test Unmarshalling with a parcel that has exceeded the limit
    Parcel parcel2;
    auto filter = std::make_shared<RSNGRenderBlurFilter>();
    ret = (filter->Marshalling(parcel2));
    EXPECT_TRUE(ret);
    RSUIFilterTypeUnderlying val = 0;
    ret = RSMarshallingHelper::Unmarshalling(parcel2, val);
    EXPECT_TRUE(ret);
    current = filter;
    for (size_t i = 1; i < RSNGRenderFilterBase::EFFECT_COUNT_LIMIT; ++i) {
        auto nextFilter = std::make_shared<RSNGRenderBlurFilter>();
        current->nextEffect_ = nextFilter;
        current = nextFilter;
    }
    ret = (filter->Marshalling(parcel2));
    EXPECT_FALSE(ret);
    std::shared_ptr<RSNGRenderFilterBase> outFilter = nullptr;
    ret = RSNGRenderFilterBase::Unmarshalling(parcel2, outFilter);
    EXPECT_TRUE(ret);
    EXPECT_EQ(outFilter, nullptr);
}

/**
 * @tc.name: AttachDetach001
 * @tc.desc: Test the Attach and Detach methods can
 *           correctly manage the node association with properties of a single filter
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, AttachDetach001, TestSize.Level1)
{
    auto filter = std::make_shared<RSNGRenderBlurFilter>();
    auto prop = filter->Getter<BlurRadiusXRenderTag>();
    auto radiusX = prop->Get();
    auto node = std::make_shared<RSRenderNode>(1);
    filter->Attach(*node, {});
    EXPECT_EQ(prop->node_.lock(), node);
    filter->Detach();
    EXPECT_EQ(prop->node_.lock(), nullptr);
    EXPECT_FLOAT_EQ(prop->Get(), radiusX);
}

/**
 * @tc.name: AttachDetach002
 * @tc.desc: Test the Attach and Detach methods can
 *           correctly manage the node association with properties of a filter chain
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, AttachDetach002, TestSize.Level1)
{
    auto filter1 = std::make_shared<RSNGRenderBlurFilter>();
    auto filter2 = std::make_shared<RSNGRenderEdgeLightFilter>();
    filter1->nextEffect_ = filter2;
    auto node = std::make_shared<RSRenderNode>(1);
    filter1->Attach(*node, {});
    EXPECT_EQ(filter1->Getter<BlurRadiusXRenderTag>()->node_.lock(), node);
    EXPECT_EQ(filter2->Getter<EdgeLightColorRenderTag>()->node_.lock(), node);
    filter1->Detach();
    EXPECT_EQ(filter1->Getter<BlurRadiusXRenderTag>()->node_.lock(), nullptr);
    EXPECT_EQ(filter2->Getter<EdgeLightColorRenderTag>()->node_.lock(), nullptr);
}

#ifndef MODIFIER_NG
/**
 * @tc.name: SetModifierType001
 * @tc.desc: Test the SetModifierType method can
 *           correctly set the modifier type for a filter's properties
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, SetModifierType001, TestSize.Level1)
{
    auto filter = std::make_shared<RSNGRenderBlurFilter>();
    auto prop = filter->Getter<BlurRadiusXRenderTag>();
    EXPECT_EQ(prop->GetModifierType(), RSModifierType::INVALID);
    auto targetType = RSModifierType::BACKGROUND_NG_FILTER;
    filter->SetModifierType(targetType);
    EXPECT_EQ(prop->GetModifierType(), targetType);
}

/**
 * @tc.name: SetModifierType002
 * @tc.desc: Test SetModifierType on a filter chain, all properties should be set.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, SetModifierTypeChain, TestSize.Level1)
{
    auto filter1 = std::make_shared<RSNGRenderBlurFilter>();
    auto filter2 = std::make_shared<RSNGRenderEdgeLightFilter>();
    filter1->nextEffect_ = filter2;
    auto targetType = RSModifierType::BACKGROUND_NG_FILTER;
    filter1->SetModifierType(targetType);
    EXPECT_EQ(filter1->Getter<BlurRadiusXRenderTag>()->GetModifierType(), targetType);
    EXPECT_EQ(filter2->Getter<EdgeLightColorRenderTag>()->GetModifierType(), targetType);
}
#endif

/**
 * @tc.name: DumpProperties001
 * @tc.desc: Test the DumpProperties method outputs correct filter properties
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, DumpProperties001, TestSize.Level1)
{
    using BlurFilter = RSNGRenderBlurFilter;
    auto filter1 = std::make_shared<BlurFilter>();
    std::string out;
    filter1->DumpProperties(out);
    EXPECT_FALSE(out.empty());
}

/**
 * @tc.name: CheckEnableEDR001
 * @tc.desc: Test the CheckEnableEDR method could check enable edr for filters
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderFilterBaseTest, CheckEnableEDR001, TestSize.Level1)
{
    std::shared_ptr<RSNGRenderFilterBase> filter1 = std::make_shared<RSNGRenderBlurFilter>();
    auto filter2 = std::make_shared<RSNGRenderEdgeLightFilter>();
    filter1->nextEffect_ = filter2;
    EXPECT_FALSE(RSUIFilterHelper::CheckEnableEDR(filter1));

    Vector4f color{0.5f, 0.5f, 1.5f, 1.0f};
    filter2->Setter<EdgeLightColorRenderTag>(color);
    EXPECT_TRUE(RSUIFilterHelper::CheckEnableEDR(filter1));
}
} // namespace OHOS::Rosen