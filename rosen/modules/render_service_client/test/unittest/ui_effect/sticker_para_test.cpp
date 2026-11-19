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
 * @tc.name: StickerEmbossParaClone001
 * @tc.desc: Verify StickerEmbossPara clone keeps all fields
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaClone001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    auto clone = para->Clone();
    ASSERT_NE(clone, nullptr);
    auto embossClone = std::static_pointer_cast<StickerEmbossPara>(clone);
    EXPECT_EQ(embossClone->GetSticker(), sticker);
    EXPECT_FLOAT_EQ(embossClone->GetOutlineWidth(), para->GetOutlineWidth());
    EXPECT_FLOAT_EQ(embossClone->GetRefractionRate(), para->GetRefractionRate());
    EXPECT_FLOAT_EQ(embossClone->GetDirIntensity(), para->GetDirIntensity());
    EXPECT_FLOAT_EQ(embossClone->GetEdgeLightWidth(), para->GetEdgeLightWidth());
    EXPECT_FLOAT_EQ(embossClone->GetEdgeLightFeatherRate(), para->GetEdgeLightFeatherRate());
    EXPECT_FLOAT_EQ(embossClone->GetEdgeLightIntensity().x_, para->GetEdgeLightIntensity().x_);
    EXPECT_FLOAT_EQ(embossClone->GetEdgeLightIntensity().y_, para->GetEdgeLightIntensity().y_);
    EXPECT_FLOAT_EQ(embossClone->GetSpotLightCenter().x_, para->GetSpotLightCenter().x_);
    EXPECT_FLOAT_EQ(embossClone->GetSpotLightCenter().y_, para->GetSpotLightCenter().y_);
    EXPECT_FLOAT_EQ(embossClone->GetSpotLightIntensity(), para->GetSpotLightIntensity());
    EXPECT_FLOAT_EQ(embossClone->GetSpecPow(), para->GetSpecPow());
    EXPECT_FLOAT_EQ(embossClone->GetSpecIntensity(), para->GetSpecIntensity());
}

/**
 * @tc.name: StickerEmbossParaMarshallingNoSticker001
 * @tc.desc: Verify Marshalling fails without a sticker pixelmap
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaMarshallingNoSticker001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    Parcel parcel;
    EXPECT_FALSE(para->Marshalling(parcel));
}

/**
 * @tc.name: StickerEmbossParaMarshallingRoundTrip001
 * @tc.desc: Verify Marshalling/Unmarshalling round trip through the dispatcher
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaMarshallingRoundTrip001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    Parcel parcel;
    EXPECT_TRUE(para->Marshalling(parcel));
    StickerEmbossPara::RegisterUnmarshallingCallback();
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_TRUE(FilterPara::Unmarshalling(parcel, val));
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(val->type_, FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    auto recovered = std::static_pointer_cast<StickerEmbossPara>(val);
    EXPECT_NE(recovered->GetSticker(), nullptr);
    EXPECT_FLOAT_EQ(recovered->GetOutlineWidth(), 2.0f);
    EXPECT_FLOAT_EQ(recovered->GetRefractionRate(), 0.4f);
    EXPECT_FLOAT_EQ(recovered->GetDirIntensity(), 0.7f);
    EXPECT_FLOAT_EQ(recovered->GetEdgeLightWidth(), 5.0f);
    EXPECT_FLOAT_EQ(recovered->GetEdgeLightFeatherRate(), 0.6f);
    EXPECT_FLOAT_EQ(recovered->GetEdgeLightIntensity().x_, 0.8f);
    EXPECT_FLOAT_EQ(recovered->GetEdgeLightIntensity().y_, 0.3f);
    EXPECT_FLOAT_EQ(recovered->GetSpotLightCenter().x_, 0.25f);
    EXPECT_FLOAT_EQ(recovered->GetSpotLightCenter().y_, 0.75f);
    EXPECT_FLOAT_EQ(recovered->GetSpotLightIntensity(), 1.2f);
    EXPECT_FLOAT_EQ(recovered->GetSpecPow(), 8.0f);
    EXPECT_FLOAT_EQ(recovered->GetSpecIntensity(), 0.9f);
}

/**
 * @tc.name: StickerEmbossParaOnUnmarshallingBadType001
 * @tc.desc: Verify OnUnmarshalling rejects a mismatched type
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaOnUnmarshallingBadType001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteUint16(static_cast<uint16_t>(FilterPara::ParaType::NONE));
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_FALSE(StickerEmbossPara::OnUnmarshalling(parcel, val));
    EXPECT_EQ(val, nullptr);
}

/**
 * @tc.name: StickerEmbossParaOnUnmarshallingEmpty001
 * @tc.desc: Verify OnUnmarshalling fails on an empty parcel
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaOnUnmarshallingEmpty001, TestSize.Level1)
{
    Parcel parcel;
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_FALSE(StickerEmbossPara::OnUnmarshalling(parcel, val));
    EXPECT_EQ(val, nullptr);
}

/**
 * @tc.name: StickerEmbossParaOnUnmarshallingBadSticker001
 * @tc.desc: Verify OnUnmarshalling fails when the sticker pixelmap payload is missing
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaOnUnmarshallingBadSticker001, TestSize.Level1)
{
    Parcel parcel;
    uint16_t type = static_cast<uint16_t>(FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    parcel.WriteUint16(type);
    parcel.WriteUint16(type);
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_FALSE(StickerEmbossPara::OnUnmarshalling(parcel, val));
    EXPECT_EQ(val, nullptr);
}

/**
 * @tc.name: StickerEmbossParaOnUnmarshallingBadParams001
 * @tc.desc: Verify OnUnmarshalling fails when float params are truncated
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaOnUnmarshallingBadParams001, TestSize.Level1)
{
    Parcel parcel;
    uint16_t type = static_cast<uint16_t>(FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    parcel.WriteUint16(type);
    parcel.WriteUint16(type);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    EXPECT_TRUE(sticker->Marshalling(parcel));
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_FALSE(StickerEmbossPara::OnUnmarshalling(parcel, val));
    EXPECT_EQ(val, nullptr);
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
    EXPECT_FLOAT_EQ(para->GetOutlineWidth(), 2.0f);
    EXPECT_FLOAT_EQ(para->GetFrequency(), 0.005f);
    EXPECT_FLOAT_EQ(para->GetDirection().x_, 1.0f);
    EXPECT_FLOAT_EQ(para->GetDirection().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetProgress(), 0.0f);
    EXPECT_FLOAT_EQ(para->GetLightDir().x_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetLightDir().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().x_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().y_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().z_, 0.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowColor().w_, 0.2f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowRadius(), 10.0f);
    EXPECT_FLOAT_EQ(para->GetElevationShadowDistance(), 10.0f);
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

/**
 * @tc.name: StickerEmbossParaIsWhitelistPara001
 * @tc.desc: Verify the emboss para is whitelisted for cross-process marshalling
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaIsWhitelistPara001, TestSize.Level1)
{
    EXPECT_TRUE(FilterPara::IsWhitelistPara(static_cast<uint16_t>(FilterPara::ParaType::STICKER_EMBOSS_FILTER)));
    EXPECT_FALSE(FilterPara::IsWhitelistPara(static_cast<uint16_t>(FilterPara::ParaType::NONE)));
}

/**
 * @tc.name: StickerEmbossParaCopyConstructor001
 * @tc.desc: Verify the copy constructor keeps every field of the emboss para
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaCopyConstructor001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    StickerEmbossPara copy(*para);
    EXPECT_EQ(copy.type_, FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    EXPECT_EQ(copy.GetSticker(), sticker);
    EXPECT_FLOAT_EQ(copy.GetOutlineWidth(), para->GetOutlineWidth());
    EXPECT_FLOAT_EQ(copy.GetRefractionRate(), para->GetRefractionRate());
    EXPECT_FLOAT_EQ(copy.GetDirIntensity(), para->GetDirIntensity());
    EXPECT_FLOAT_EQ(copy.GetEdgeLightWidth(), para->GetEdgeLightWidth());
    EXPECT_FLOAT_EQ(copy.GetEdgeLightFeatherRate(), para->GetEdgeLightFeatherRate());
    EXPECT_FLOAT_EQ(copy.GetEdgeLightIntensity().x_, para->GetEdgeLightIntensity().x_);
    EXPECT_FLOAT_EQ(copy.GetEdgeLightIntensity().y_, para->GetEdgeLightIntensity().y_);
    EXPECT_FLOAT_EQ(copy.GetSpotLightCenter().x_, para->GetSpotLightCenter().x_);
    EXPECT_FLOAT_EQ(copy.GetSpotLightCenter().y_, para->GetSpotLightCenter().y_);
    EXPECT_FLOAT_EQ(copy.GetSpotLightIntensity(), para->GetSpotLightIntensity());
    EXPECT_FLOAT_EQ(copy.GetSpecPow(), para->GetSpecPow());
    EXPECT_FLOAT_EQ(copy.GetSpecIntensity(), para->GetSpecIntensity());
}

/**
 * @tc.name: FilterMarshallingRoundTrip001
 * @tc.desc: Verify a Filter container holding an emboss para survives a Marshalling round trip
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, FilterMarshallingRoundTrip001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);
    auto filter = std::make_shared<Filter>();
    ASSERT_NE(filter, nullptr);
    filter->AddPara(para);

    Parcel parcel;
    EXPECT_TRUE(filter->Marshalling(parcel));
    StickerEmbossPara::RegisterUnmarshallingCallback();
    std::shared_ptr<Filter> val = nullptr;
    EXPECT_TRUE(Filter::Unmarshalling(parcel, val));
    ASSERT_NE(val, nullptr);

    const auto& paras = val->GetAllPara();
    ASSERT_EQ(paras.size(), 1u);
    EXPECT_EQ(paras[0]->type_, FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    auto recovered = std::static_pointer_cast<StickerEmbossPara>(paras[0]);
    EXPECT_NE(recovered->GetSticker(), nullptr);
    EXPECT_FLOAT_EQ(recovered->GetOutlineWidth(), 2.0f);
    EXPECT_FLOAT_EQ(recovered->GetSpecIntensity(), 0.9f);
}

/**
 * @tc.name: StickerEmbossParaMarshallingTypeWriteFail001
 * @tc.desc: Verify Marshalling fails when the parcel cannot hold the type header
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaMarshallingTypeWriteFail001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    Parcel parcel;
    EXPECT_TRUE(parcel.SetMaxCapacity(sizeof(uint16_t)));
    EXPECT_FALSE(para->Marshalling(parcel));
}

/**
 * @tc.name: StickerEmbossParaMarshallingParaWriteFail001
 * @tc.desc: Verify Marshalling fails when the parcel runs out mid-way through the float block
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaMarshallingParaWriteFail001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    Parcel scratch;
    ASSERT_TRUE(para->Marshalling(scratch));
    const size_t fullSize = scratch.GetDataSize();

    Parcel parcel;
    EXPECT_TRUE(parcel.SetMaxCapacity(fullSize - sizeof(float)));
    EXPECT_FALSE(para->Marshalling(parcel));
}

/**
 * @tc.name: StickerEmbossParaOnUnmarshallingLightIncomplete001
 * @tc.desc: Verify OnUnmarshalling fails when only 9 of 12 floats are present
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaOnUnmarshallingLightIncomplete001, TestSize.Level1)
{
    Parcel parcel;
    uint16_t type = static_cast<uint16_t>(FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    ASSERT_TRUE(parcel.WriteUint16(type));
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    ASSERT_TRUE(sticker->Marshalling(parcel));
    for (int i = 0; i < 9; ++i) {
        ASSERT_TRUE(parcel.WriteFloat(0.5f));
    }
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_FALSE(StickerEmbossPara::OnUnmarshalling(parcel, val));
    EXPECT_EQ(val, nullptr);
}

/**
 * @tc.name: StickerEmbossParaOnUnmarshallingBaseTruncated001
 * @tc.desc: Verify OnUnmarshalling fails when only 3 of 12 floats are present
 * @tc.type: FUNC
 */
HWTEST_F(RSStickerParaTest, StickerEmbossParaOnUnmarshallingBaseTruncated001, TestSize.Level1)
{
    Parcel parcel;
    uint16_t type = static_cast<uint16_t>(FilterPara::ParaType::STICKER_EMBOSS_FILTER);
    ASSERT_TRUE(parcel.WriteUint16(type));
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    ASSERT_TRUE(sticker->Marshalling(parcel));
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(parcel.WriteFloat(0.5f));
    }
    std::shared_ptr<FilterPara> val = nullptr;
    EXPECT_FALSE(StickerEmbossPara::OnUnmarshalling(parcel, val));
    EXPECT_EQ(val, nullptr);
}
} // namespace Rosen
} // namespace OHOS
