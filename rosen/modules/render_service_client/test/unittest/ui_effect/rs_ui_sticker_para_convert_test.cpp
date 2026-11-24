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
#include "filter/include/filter_sticker_emboss_para.h"
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

void SetAllEmbossFields(const std::shared_ptr<StickerEmbossPara>& para,
    const std::shared_ptr<Media::PixelMap>& sticker)
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

void SetAllLaserFields(const std::shared_ptr<StickerLaserShaderEffectPara>& para,
    const std::shared_ptr<Media::PixelMap>& sticker)
{
    para->SetSticker(sticker);
    para->SetOutlineWidth(4.0f);
    para->SetFrequency(0.02f);
    para->SetDirection(Vector2f(0.0f, 1.0f));
    para->SetProgress(0.5f);
    para->SetLightDir(Vector2f(0.3f, 0.7f));
    para->SetElevationShadowColor(Vector4f(0.1f, 0.2f, 0.3f, 0.4f));
    para->SetElevationShadowRadius(20.0f);
    para->SetElevationShadowDistance(30.0f);
}
} // namespace

class RSUIStickerParaConvertTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name: CreateStickerEmbossFilterByType001
 * @tc.desc: Verify the UI filter factory creates an emboss NG filter for the sticker type
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, CreateStickerEmbossFilterByType001, TestSize.Level1)
{
    auto filter = RSNGFilterBase::Create(RSNGEffectType::STICKER_EMBOSS_FILTER);
    ASSERT_NE(filter, nullptr);
    auto embossFilter = std::static_pointer_cast<RSNGStickerEmbossFilter>(filter);
    EXPECT_NE(embossFilter, nullptr);
}

/**
 * @tc.name: ConvertStickerEmbossParaFull001
 * @tc.desc: Verify all 11 emboss para fields are mapped onto the NG filter tags
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, ConvertStickerEmbossParaFull001, TestSize.Level1)
{
    auto para = std::make_shared<StickerEmbossPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllEmbossFields(para, sticker);

    auto filter = RSNGFilterBase::Create(para);
    ASSERT_NE(filter, nullptr);
    auto embossFilter = std::static_pointer_cast<RSNGStickerEmbossFilter>(filter);
    ASSERT_NE(embossFilter, nullptr);

    EXPECT_EQ(embossFilter->Getter<StickerEmbossStickerTag>()->Get(), sticker);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossOutlineWidthTag>()->Get(), 2.0f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossRefractionRateTag>()->Get(), 0.4f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossDirIntensityTag>()->Get(), 0.7f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossEdgeLightWidthTag>()->Get(), 5.0f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossEdgeLightFeatherRateTag>()->Get(), 0.6f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossEdgeLightIntensityTag>()->Get().x_, 0.8f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossEdgeLightIntensityTag>()->Get().y_, 0.3f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossSpotLightCenterTag>()->Get().x_, 0.25f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossSpotLightCenterTag>()->Get().y_, 0.75f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossSpotLightIntensityTag>()->Get(), 1.2f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossSpecPowTag>()->Get(), 8.0f);
    EXPECT_FLOAT_EQ(embossFilter->Getter<StickerEmbossSpecIntensityTag>()->Get(), 0.9f);
}

/**
 * @tc.name: ConvertStickerEmbossParaNull001
 * @tc.desc: Verify the UI filter factory rejects a null para
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, ConvertStickerEmbossParaNull001, TestSize.Level1)
{
    EXPECT_EQ(RSNGFilterBase::Create(nullptr), nullptr);
}

/**
 * @tc.name: ConvertStickerEmbossParaUnknownType001
 * @tc.desc: Verify the UI filter factory rejects an unregistered effect type
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, ConvertStickerEmbossParaUnknownType001, TestSize.Level1)
{
    EXPECT_EQ(RSNGFilterBase::Create(RSNGEffectType::INVALID), nullptr);
}

/**
 * @tc.name: CreateStickerLaserShaderByType001
 * @tc.desc: Verify the UI shader factory creates a laser NG shader for the sticker type
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, CreateStickerLaserShaderByType001, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::STICKER_LASER_SHADER);
    ASSERT_NE(shader, nullptr);
    auto laserShader = std::static_pointer_cast<RSNGStickerLaserShader>(shader);
    EXPECT_NE(laserShader, nullptr);
}

/**
 * @tc.name: ConvertStickerLaserShaderParaFull001
 * @tc.desc: Verify all 9 laser para fields are mapped onto the NG shader tags
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, ConvertStickerLaserShaderParaFull001, TestSize.Level1)
{
    auto para = std::make_shared<StickerLaserShaderEffectPara>();
    ASSERT_NE(para, nullptr);
    auto sticker = MakeStickerPixelMap();
    ASSERT_NE(sticker, nullptr);
    SetAllLaserFields(para, sticker);

    auto shader = RSNGShaderBase::Create(para);
    ASSERT_NE(shader, nullptr);
    auto laserShader = std::static_pointer_cast<RSNGStickerLaserShader>(shader);
    ASSERT_NE(laserShader, nullptr);

    EXPECT_EQ(laserShader->Getter<StickerLaserShaderStickerTag>()->Get(), sticker);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderOutlineWidthTag>()->Get(), 4.0f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderFrequencyTag>()->Get(), 0.02f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderDirectionTag>()->Get().x_, 0.0f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderDirectionTag>()->Get().y_, 1.0f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderProgressTag>()->Get(), 0.5f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderLightDirTag>()->Get().x_, 0.3f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderLightDirTag>()->Get().y_, 0.7f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderElevationShadowColorTag>()->Get().x_, 0.1f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderElevationShadowColorTag>()->Get().w_, 0.4f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderElevationShadowRadiusTag>()->Get(), 20.0f);
    EXPECT_FLOAT_EQ(laserShader->Getter<StickerLaserShaderElevationShadowDistanceTag>()->Get(), 30.0f);
}

/**
 * @tc.name: ConvertStickerLaserShaderParaNull001
 * @tc.desc: Verify the UI shader factory rejects a null para
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, ConvertStickerLaserShaderParaNull001, TestSize.Level1)
{
    EXPECT_EQ(RSNGShaderBase::Create(nullptr), nullptr);
}

/**
 * @tc.name: ConvertStickerLaserShaderParaUnknownType001
 * @tc.desc: Verify the UI shader factory rejects an unregistered effect type
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, ConvertStickerLaserShaderParaUnknownType001, TestSize.Level1)
{
    EXPECT_EQ(RSNGShaderBase::Create(RSNGEffectType::INVALID), nullptr);
}

/**
 * @tc.name: StickerUIContainsTags001
 * @tc.desc: Verify all sticker tags are registered on the UI NG classes
 * @tc.type: FUNC
 */
HWTEST_F(RSUIStickerParaConvertTest, StickerUIContainsTags001, TestSize.Level1)
{
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossStickerTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossOutlineWidthTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossRefractionRateTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossDirIntensityTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossEdgeLightWidthTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossEdgeLightFeatherRateTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossEdgeLightIntensityTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossSpotLightCenterTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossSpotLightIntensityTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossSpecPowTag>()));
    EXPECT_TRUE((RSNGStickerEmbossFilter::Contains<StickerEmbossSpecIntensityTag>()));
    EXPECT_FALSE((RSNGStickerEmbossFilter::Contains<StickerLaserShaderFrequencyTag>()));

    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderStickerTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderOutlineWidthTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderFrequencyTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderDirectionTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderProgressTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderLightDirTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderElevationShadowColorTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderElevationShadowRadiusTag>()));
    EXPECT_TRUE((RSNGStickerLaserShader::Contains<StickerLaserShaderElevationShadowDistanceTag>()));
    EXPECT_FALSE((RSNGStickerLaserShader::Contains<StickerEmbossOutlineWidthTag>()));
}
} // namespace Rosen
} // namespace OHOS
