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

#include <gtest/gtest.h>

#include "effect/rs_render_filter_base.h"
#include "effect/rs_render_shader_base.h"
#include "ge_visual_effect.h"
#include "ge_visual_effect_container.h"
#include "parcel.h"
#include "pixel_map.h"

namespace OHOS {
namespace Rosen {

using namespace testing;
using namespace testing::ext;

namespace {
std::shared_ptr<Media::PixelMap> MakeStickerPixelMap(int32_t width = 16, int32_t height = 16)
{
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    return std::shared_ptr<Media::PixelMap>(Media::PixelMap::Create(opts));
}
} // namespace

class RSRenderStickerEffectTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name: CreateStickerEmbossFilter001
 * @tc.desc: Verify the render filter factory creates the sticker emboss filter
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, CreateStickerEmbossFilter001, TestSize.Level1)
{
    auto filter = RSNGRenderFilterBase::Create(RSNGEffectType::STICKER_EMBOSS_FILTER);
    ASSERT_NE(filter, nullptr);
    EXPECT_EQ(filter->GetType(), RSNGEffectType::STICKER_EMBOSS_FILTER);
    auto embossFilter = std::static_pointer_cast<RSNGRenderStickerEmbossFilter>(filter);
    ASSERT_NE(embossFilter, nullptr);
    EXPECT_TRUE(RSNGRenderStickerEmbossFilter::Contains<StickerEmbossOutlineWidthRenderTag>());
}

/**
 * @tc.name: CreateStickerLaserShader001
 * @tc.desc: Verify the render shader factory creates the sticker laser shader
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, CreateStickerLaserShader001, TestSize.Level1)
{
    auto shader = RSNGRenderShaderBase::Create(RSNGEffectType::STICKER_LASER_SHADER);
    ASSERT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::STICKER_LASER_SHADER);
    auto laserShader = std::static_pointer_cast<RSNGRenderStickerLaserShader>(shader);
    ASSERT_NE(laserShader, nullptr);
    EXPECT_TRUE(RSNGRenderStickerLaserShader::Contains<StickerLaserShaderFrequencyRenderTag>());
}

/**
 * @tc.name: CreateStickerEffectInvalidType001
 * @tc.desc: Verify both factories reject an invalid effect type
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, CreateStickerEffectInvalidType001, TestSize.Level1)
{
    EXPECT_EQ(RSNGRenderFilterBase::Create(RSNGEffectType::INVALID), nullptr);
    EXPECT_EQ(RSNGRenderShaderBase::Create(RSNGEffectType::INVALID), nullptr);
}

/**
 * @tc.name: GetEffectTypeStringSticker001
 * @tc.desc: Verify the sticker effect type strings match the GE params name registry
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, GetEffectTypeStringSticker001, TestSize.Level1)
{
    EXPECT_EQ(RSNGRenderEffectHelper::GetEffectTypeString(RSNGEffectType::STICKER_LASER_SHADER), "StickerLaser");
    EXPECT_EQ(RSNGRenderEffectHelper::GetEffectTypeString(RSNGEffectType::STICKER_EMBOSS_FILTER),
        "StickerEmbossFilter");
    EXPECT_EQ(RSNGRenderEffectHelper::GetEffectTypeString(RSNGEffectType::INVALID), "Invalid");
}

/**
 * @tc.name: StickerEmbossTagSetGet001
 * @tc.desc: Verify the emboss render property tags round-trip through Setter/Getter
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, StickerEmbossTagSetGet001, TestSize.Level1)
{
    auto filter = RSNGRenderFilterBase::Create(RSNGEffectType::STICKER_EMBOSS_FILTER);
    ASSERT_NE(filter, nullptr);
    auto embossFilter = std::static_pointer_cast<RSNGRenderStickerEmbossFilter>(filter);
    ASSERT_NE(embossFilter, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);

    embossFilter->Setter<StickerEmbossOutlineWidthRenderTag>(2.0f);
    embossFilter->Setter<StickerEmbossEdgeLightIntensityRenderTag>(Vector2f(0.8f, 0.3f));
    embossFilter->Setter<StickerEmbossSpecIntensityRenderTag>(0.9f);
    embossFilter->Setter<StickerEmbossStickerRenderTag>(sticker);

    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossOutlineWidthRenderTag>()->Get(), 2.0f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossEdgeLightIntensityRenderTag>()->Get().x_, 0.8f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossEdgeLightIntensityRenderTag>()->Get().y_, 0.3f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossSpecIntensityRenderTag>()->Get(), 0.9f);
    EXPECT_EQ(embossFilter->Getter<StickerEmbossStickerRenderTag>()->Get(), sticker);
}

/**
 * @tc.name: StickerLaserTagSetGet001
 * @tc.desc: Verify the laser render property tags round-trip through Setter/Getter
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, StickerLaserTagSetGet001, TestSize.Level1)
{
    auto shader = RSNGRenderShaderBase::Create(RSNGEffectType::STICKER_LASER_SHADER);
    ASSERT_NE(shader, nullptr);
    auto laserShader = std::static_pointer_cast<RSNGRenderStickerLaserShader>(shader);
    ASSERT_NE(laserShader, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);

    laserShader->Setter<StickerLaserShaderFrequencyRenderTag>(0.01f);
    laserShader->Setter<StickerLaserShaderProgressRenderTag>(0.5f);
    laserShader->Setter<StickerLaserShaderDirectionRenderTag>(Vector2f(1.0f, 0.0f));
    laserShader->Setter<StickerLaserShaderElevationShadowColorRenderTag>(Vector4f(0.1f, 0.2f, 0.3f, 0.4f));
    laserShader->Setter<StickerLaserShaderStickerRenderTag>(sticker);

    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderFrequencyRenderTag>()->Get(), 0.01f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderProgressRenderTag>()->Get(), 0.5f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderDirectionRenderTag>()->Get().x_, 1.0f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderDirectionRenderTag>()->Get().y_, 0.0f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderElevationShadowColorRenderTag>()->Get().x_, 0.1f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderElevationShadowColorRenderTag>()->Get().w_, 0.4f);
    EXPECT_EQ(laserShader->Getter<StickerLaserShaderStickerRenderTag>()->Get(), sticker);
}

/**
 * @tc.name: StickerEmbossContainsAllTags001
 * @tc.desc: Verify all 11 emboss tags are registered on the render filter
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, StickerEmbossContainsAllTags001, TestSize.Level1)
{
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossStickerRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossOutlineWidthRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossRefractionRateRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossDirIntensityRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossEdgeLightWidthRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossEdgeLightFeatherRateRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossEdgeLightIntensityRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossSpotLightCenterRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossSpotLightIntensityRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossSpecPowRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerEmbossFilter::Contains<StickerEmbossSpecIntensityRenderTag>()));
    // A laser tag must not be registered on the emboss filter
    EXPECT_FALSE((RSNGRenderStickerEmbossFilter::Contains<StickerLaserShaderFrequencyRenderTag>()));
}

/**
 * @tc.name: StickerLaserContainsAllTags001
 * @tc.desc: Verify all 9 laser tags are registered on the render shader
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, StickerLaserContainsAllTags001, TestSize.Level1)
{
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderStickerRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderOutlineWidthRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderFrequencyRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderDirectionRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderProgressRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderLightDirRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderElevationShadowColorRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderElevationShadowRadiusRenderTag>()));
    EXPECT_TRUE((RSNGRenderStickerLaserShader::Contains<StickerLaserShaderElevationShadowDistanceRenderTag>()));
    // An emboss tag must not be registered on the laser shader
    EXPECT_FALSE((RSNGRenderStickerLaserShader::Contains<StickerEmbossOutlineWidthRenderTag>()));
}

/**
 * @tc.name: StickerEffectUpdateToGEContainer001
 * @tc.desc: Verify the sticker effects land in the GE container and their description is reported
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, StickerEffectUpdateToGEContainer001, TestSize.Level1)
{
    auto filter = RSNGRenderFilterBase::Create(RSNGEffectType::STICKER_EMBOSS_FILTER);
    ASSERT_NE(filter, nullptr);
    auto embossFilter = std::static_pointer_cast<RSNGRenderStickerEmbossFilter>(filter);
    ASSERT_NE(embossFilter, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    embossFilter->Setter<StickerEmbossOutlineWidthRenderTag>(2.0f);
    embossFilter->Setter<StickerEmbossStickerRenderTag>(sticker);

    RSNGRenderFilterHelper::GenerateGEVisualEffect(filter);
    ASSERT_NE(filter->geFilter_, nullptr);
    EXPECT_EQ(filter->geFilter_->GetName(), "StickerEmbossFilter");

    auto container = std::make_shared<Drawing::GEVisualEffectContainer>();
    ASSERT_NE(container, nullptr);
    RSNGRenderFilterHelper::UpdateToGEContainer(filter, container);
    ASSERT_EQ(container->GetFilters().size(), 1u);
    EXPECT_EQ(container->GetFilters()[0]->GetName(), "StickerEmbossFilter");

    // Null guards keep the container unchanged without crashing
    std::shared_ptr<RSNGRenderFilterBase> nullFilter = nullptr;
    RSNGRenderFilterHelper::UpdateToGEContainer(nullFilter, container);
    std::shared_ptr<Drawing::GEVisualEffectContainer> nullContainer = nullptr;
    RSNGRenderFilterHelper::UpdateToGEContainer(filter, nullContainer);
    EXPECT_EQ(container->GetFilters().size(), 1u);

    std::string description;
    RSNGRenderFilterHelper::GetDescription(filter, description);
    EXPECT_NE(description.find("StickerEmbossFilter"), std::string::npos);
    RSNGRenderFilterHelper::GetDescription(nullFilter, description);
    EXPECT_NE(description.find("StickerEmbossFilter"), std::string::npos);

    // The laser shader appends itself to the container
    auto shader = RSNGRenderShaderBase::Create(RSNGEffectType::STICKER_LASER_SHADER);
    ASSERT_NE(shader, nullptr);
    auto laserShader = std::static_pointer_cast<RSNGRenderStickerLaserShader>(shader);
    ASSERT_NE(laserShader, nullptr);
    laserShader->Setter<StickerLaserShaderFrequencyRenderTag>(0.01f);
    shader->AppendToGEContainer(container);
    EXPECT_EQ(container->GetFilters().size(), 2u);
    EXPECT_EQ(container->GetFilters()[1]->GetName(), "StickerLaser");
    shader->AppendToGEContainer(nullContainer);
    EXPECT_EQ(container->GetFilters().size(), 2u);
}

/**
 * @tc.name: StickerEffectMarshallingRoundTrip001
 * @tc.desc: Verify the sticker effects survive a Marshalling/Unmarshalling round trip
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderStickerEffectTest, StickerEffectMarshallingRoundTrip001, TestSize.Level1)
{
    // Emboss filter round trip
    auto filter = RSNGRenderFilterBase::Create(RSNGEffectType::STICKER_EMBOSS_FILTER);
    ASSERT_NE(filter, nullptr);
    auto embossFilter = std::static_pointer_cast<RSNGRenderStickerEmbossFilter>(filter);
    ASSERT_NE(embossFilter, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    embossFilter->Setter<StickerEmbossOutlineWidthRenderTag>(2.0f);
    embossFilter->Setter<StickerEmbossEdgeLightIntensityRenderTag>(Vector2f(0.8f, 0.3f));
    embossFilter->Setter<StickerEmbossSpecIntensityRenderTag>(0.9f);
    embossFilter->Setter<StickerEmbossStickerRenderTag>(sticker);

    Parcel parcel;
    EXPECT_TRUE(filter->Marshalling(parcel));
    std::shared_ptr<RSNGRenderFilterBase> recoveredFilter = nullptr;
    EXPECT_TRUE(RSNGRenderFilterBase::Unmarshalling(parcel, recoveredFilter));
    ASSERT_NE(recoveredFilter, nullptr);
    EXPECT_EQ(recoveredFilter->GetType(), RSNGEffectType::STICKER_EMBOSS_FILTER);
    auto recoveredEmbossFilter = std::static_pointer_cast<RSNGRenderStickerEmbossFilter>(recoveredFilter);
    ASSERT_NE(recoveredEmbossFilter, nullptr);
    EXPECT_FLOAT_EQ(recoveredEmbossFilter->Getter<StickerEmbossOutlineWidthRenderTag>()->Get(), 2.0f);
    EXPECT_FLOAT_EQ(recoveredEmbossFilter->Getter<StickerEmbossEdgeLightIntensityRenderTag>()->Get().x_, 0.8f);
    EXPECT_FLOAT_EQ(recoveredEmbossFilter->Getter<StickerEmbossEdgeLightIntensityRenderTag>()->Get().y_, 0.3f);
    EXPECT_FLOAT_EQ(recoveredEmbossFilter->Getter<StickerEmbossSpecIntensityRenderTag>()->Get(), 0.9f);
    EXPECT_NE(recoveredEmbossFilter->Getter<StickerEmbossStickerRenderTag>()->Get(), nullptr);

    // Laser shader round trip
    auto shader = RSNGRenderShaderBase::Create(RSNGEffectType::STICKER_LASER_SHADER);
    ASSERT_NE(shader, nullptr);
    auto laserShader = std::static_pointer_cast<RSNGRenderStickerLaserShader>(shader);
    ASSERT_NE(laserShader, nullptr);
    laserShader->Setter<StickerLaserShaderFrequencyRenderTag>(0.01f);
    laserShader->Setter<StickerLaserShaderProgressRenderTag>(0.5f);
    laserShader->Setter<StickerLaserShaderElevationShadowColorRenderTag>(Vector4f(0.1f, 0.2f, 0.3f, 0.4f));
    laserShader->Setter<StickerLaserShaderStickerRenderTag>(sticker);

    Parcel shaderParcel;
    EXPECT_TRUE(shader->Marshalling(shaderParcel));
    std::shared_ptr<RSNGRenderShaderBase> recoveredShader = nullptr;
    EXPECT_TRUE(RSNGRenderShaderBase::Unmarshalling(shaderParcel, recoveredShader));
    ASSERT_NE(recoveredShader, nullptr);
    EXPECT_EQ(recoveredShader->GetType(), RSNGEffectType::STICKER_LASER_SHADER);
    auto recoveredLaserShader = std::static_pointer_cast<RSNGRenderStickerLaserShader>(recoveredShader);
    ASSERT_NE(recoveredLaserShader, nullptr);
    EXPECT_FLOAT_EQ(recoveredLaserShader->Getter<StickerLaserShaderFrequencyRenderTag>()->Get(), 0.01f);
    EXPECT_FLOAT_EQ(recoveredLaserShader->Getter<StickerLaserShaderProgressRenderTag>()->Get(), 0.5f);
    EXPECT_FLOAT_EQ(recoveredLaserShader->Getter<StickerLaserShaderElevationShadowColorRenderTag>()->Get().w_, 0.4f);
    EXPECT_NE(recoveredLaserShader->Getter<StickerLaserShaderStickerRenderTag>()->Get(), nullptr);
}
} // namespace Rosen
} // namespace OHOS
