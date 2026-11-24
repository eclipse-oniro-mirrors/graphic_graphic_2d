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

#include <vector>

#include <gtest/gtest.h>

#include "effect/include/sticker_laser_shader_effect_para.h"
#include "effect/include/visual_effect.h"
#include "filter/include/filter.h"
#include "filter/include/filter_sticker_emboss_para.h"
#include "parcel.h"
#include "pixel_map.h"
#include "property/include/rs_ui_filter_base.h"
#include "property/include/rs_ui_shader_base.h"

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

void SetAllEmbossFields(const std::shared_ptr<StickerEmbossPara>& para, const std::shared_ptr<Media::PixelMap>& sticker)
{
    para->SetSticker(sticker);
    para->SetOutlineWidth(2.0f);
    para->SetRefractionRate(0.4f);
    para->SetDirIntensity(0.7f);
    para->SetEdgeLightWidth(5.0f);
    para->SetEdgeLightFeatherRate(0.6f);
    para->SetEdgeLightIntensity(Vector2f(0.8f, 0.3f));
    para->SetSpotLightCenter(Vector2f(0.25f, 0.75f));
    para->SetSpotLightIntensity(1.2f);
    para->SetSpecPow(8.0f);
    para->SetSpecIntensity(0.9f);
}
} // namespace

class RSStickerParaTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSStickerParaTest::SetUpTestCase() {}
void RSStickerParaTest::TearDownTestCase() {}
void RSStickerParaTest::SetUp() {}
void RSStickerParaTest::TearDown() {}

/**
 * @tc.name: StickerEmbossParaType001
 * @tc.desc: Verify StickerEmbossPara type is STICKER_EMBOSS_FILTER
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaType001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    EXPECT_EQ(para->type_, FilterPara::ParaType::STICKER_EMBOSS_FILTER);
}

/**
 * @tc.name: StickerEmbossParaDefaultValues001
 * @tc.desc: Verify StickerEmbossPara default values
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaDefaultValues001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    EXPECT_EQ(para->GetSticker(), nullptr);
    EXPECT_FLOAT_EQ(para->GetOutlineWidth(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetRefractionRate(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetDirIntensity(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightWidth(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightFeatherRate(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightIntensity().x_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightIntensity().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetSpotLightCenter().x_, 0.5f);
    EXPECT_FLOAT_EQ(para->GetSpotLightCenter().y_, 0.5f);
    EXPECT_FLOAT_EQ(para->GetSpotLightIntensity(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetSpecPow(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetSpecIntensity(), 0.0f);
}

/**
 * @tc.name: StickerEmbossParaSetterGetter001
 * @tc.desc: Verify StickerEmbossPara setters and getters
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaSetterGetter001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    EXPECT_EQ(para->GetSticker(), sticker);
    EXPECT_FLOAT_EQ(para->GetOutlineWidth(), 2.0f);
    EXPECT_FLOAT_EQ(para->GetRefractionRate(), 0.4f);
    EXPECT_FLOAT_EQ(para->GetDirIntensity(), 0.7f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightWidth(), 5.0f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightFeatherRate(), 0.6f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightIntensity().x_, 0.8f);
    EXPECT_FLOAT_EQ(para->GetEdgeLightIntensity().y_, 0.3f);
    EXPECT_FLOAT_EQ(para->GetSpotLightCenter().x_, 0.25f);
    EXPECT_FLOAT_EQ(para->GetSpotLightCenter().y_, 0.75f);
    EXPECT_FLOAT_EQ(para->GetSpotLightIntensity(), 1.2f);
    EXPECT_FLOAT_EQ(para->GetSpecPow(), 8.0f);
    EXPECT_FLOAT_EQ(para->GetSpecIntensity(), 0.9f);
}

/**
 * @tc.name: StickerEmbossParaMarshallingUnsupported001
 * @tc.desc: The emboss para is client-side only; base Marshalling/Clone report unsupported
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaMarshallingUnsupported001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    Parcel parcel;
    EXPECT_FALSE(para->Marshalling(parcel));
    EXPECT_EQ(para->Clone(), nullptr);
    EXPECT_FALSE(FilterPara::IsWhitelistPara(static_cast<uint16_t>(FilterPara::ParaType::STICKER_EMBOSS_FILTER)));
}

/**
 * @tc.name: StickerEmbossParaCreateNGFilter001
 * @tc.desc: Verify RSNGFilterBase::Create converts a StickerEmbossPara
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaCreateNGFilter001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);
    auto filter = RSNGFilterBase::Create(para);
    EXPECT_NE(filter, nullptr);
}

/**
 * @tc.name: StickerEmbossParaCreateNGFilterNull001
 * @tc.desc: Verify RSNGFilterBase::Create rejects a null para
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaCreateNGFilterNull001, TestSize.Level1)
{
    EXPECT_EQ(RSNGFilterBase::Create(nullptr), nullptr);
}

/**
 * @tc.name: FilterAddStickerEmbossPara001
 * @tc.desc: Verify Filter accepts a StickerEmbossPara
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, FilterAddStickerEmbossPara001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto filter = std::make_shared<Filter>();
    ASSERT_NE(filter, nullptr);
    filter->AddPara(para);
    SUCCEED();
}

/**
 * @tc.name: StickerLaserShaderParaType001
 * @tc.desc: Verify StickerLaserShaderEffectPara type is STICKER_LASER_SHADER
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerLaserShaderParaType001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    EXPECT_EQ(para->type_, VisualEffectPara::ParaType::STICKER_LASER_SHADER);
}

/**
 * @tc.name: StickerLaserShaderParaDefaultValues001
 * @tc.desc: Verify StickerLaserShaderEffectPara default values
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerLaserShaderParaDefaultValues001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    EXPECT_EQ(para->GetSticker(), nullptr);
    EXPECT_FLOAT_EQ(para->GetOutlineWidth(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetFrequency(), 0.005f);
    EXPECT_FLOAT_EQ(para->GetDirection().x_, 1.0f);
    EXPECT_FLOAT_EQ(para->GetDirection().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetProgress(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetLightDir().x_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetLightDir().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().x_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().z_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().w_, 26.0f / 255.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowRadius(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowDistance(), 0.0f);
}

/**
 * @tc.name: StickerLaserShaderParaSetterGetter001
 * @tc.desc: Verify StickerLaserShaderEffectPara setters and getters
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerLaserShaderParaSetterGetter001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);

    para->SetSticker(sticker);
    EXPECT_EQ(para->GetSticker(), sticker);
    para->SetOutlineWidth(4.0f);
    EXPECT_FLOAT_EQ(para->GetOutlineWidth(), 4.0f);
    para->SetFrequency(0.02f);
    EXPECT_FLOAT_EQ(para->GetFrequency(), 0.02f);
    para->SetDirection(Vector2f(0.0f, 1.0f));
    EXPECT_FLOAT_EQ(para->GetDirection().x_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetDirection().y_, 1.0f);
    para->SetProgress(0.5f);
    EXPECT_FLOAT_EQ(para->GetProgress(), 0.5f);
    para->SetLightDir(Vector2f(0.3f, 0.7f));
    EXPECT_FLOAT_EQ(para->GetLightDir().x_, 0.3f);
    EXPECT_FLOAT_EQ(para->GetLightDir().y_, 0.7f);
    para->SetElevationShadowColor(Vector4f(0.1f, 0.2f, 0.3f, 0.4f));
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().x_, 0.1f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().y_, 0.2f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().z_, 0.3f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().w_, 0.4f);
    para->SetElevationShadowRadius(20.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowRadius(), 20.0f);
    para->SetElevationShadowDistance(30.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowDistance(), 30.0f);
}

/**
 * @tc.name: VisualEffectAddStickerLaserPara001
 * @tc.desc: Verify VisualEffect accepts a StickerLaserShaderEffectPara
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, VisualEffectAddStickerLaserPara001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    auto visualEffect = std::make_shared<VisualEffect>();
    ASSERT_NE(visualEffect, nullptr);
    visualEffect->AddPara(para);
    SUCCEED();
}

/**
 * @tc.name: StickerLaserShaderParaCreateNGShader001
 * @tc.desc: Verify RSNGShaderBase::Create converts a StickerLaserShaderEffectPara
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerLaserShaderParaCreateNGShader001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    para->SetSticker(sticker);
    para->SetOutlineWidth(3.0f);
    para->SetFrequency(0.01f);
    para->SetProgress(0.8f);
    auto shader = RSNGShaderBase::Create(para);
    EXPECT_NE(shader, nullptr);
}

/**
 * @tc.name: StickerLaserShaderParaCreateNGShaderNull001
 * @tc.desc: Verify RSNGShaderBase::Create rejects a null para
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerLaserShaderParaCreateNGShaderNull001, TestSize.Level1)
{
    EXPECT_EQ(RSNGShaderBase::Create(nullptr), nullptr);
}

/**
 * @tc.name: StickerLaserShaderParaMarshallingUnsupported001
 * @tc.desc: The laser para is client-side only; base Marshalling/Clone report unsupported
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerLaserShaderParaMarshallingUnsupported001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    Parcel parcel;
    EXPECT_FALSE(para->Marshalling(parcel));
    EXPECT_EQ(para->Clone(), nullptr);
}
} // namespace Rosen
} // namespace OHOS
