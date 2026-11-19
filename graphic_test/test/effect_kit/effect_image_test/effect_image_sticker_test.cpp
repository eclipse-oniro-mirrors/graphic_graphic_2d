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

#include <algorithm>
#include <array>
#include <memory>
#include <vector>
#include "image_source.h"
#include "pixel_map.h"
#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"
#include "rs_graphic_test_director.h"
#include "skia_effectChain/include/effect_image_render.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

namespace {
const std::string TEST_IMAGE_PATH = "/data/local/tmp/Images/backGroundImage.jpg";
const int SCREEN_WIDTH = 1200;
const int SCREEN_HEIGHT = 2000;
constexpr size_t BOUNDS_WIDTH_INDEX = 2;
constexpr size_t BOUNDS_HEIGHT_INDEX = 3;

const std::array embossOutlineWidthValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossRefractionRateValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossDirIntensityValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossEdgeLightWidthValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossEdgeLightFeatherRateValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossEdgeLightIntensityValues = { Vector2f { 0.0f, 0.0f }, Vector2f { 1.0f, 1.0f },
    Vector2f { 10.0f, 10.0f }, Vector2f { 50.0f, 50.0f } };
const std::array embossSpotLightCenterValues = { Vector2f { 0.0f, 0.0f }, Vector2f { 1.0f, 1.0f },
    Vector2f { 10.0f, 10.0f }, Vector2f { 50.0f, 50.0f } };
const std::array embossSpotLightIntensityValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossSpecPowValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array embossSpecIntensityValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const size_t EMBOSS_COMBINATION_COUNT = std::max({ embossOutlineWidthValues.size(),
    embossRefractionRateValues.size(), embossDirIntensityValues.size(), embossEdgeLightWidthValues.size(),
    embossEdgeLightFeatherRateValues.size(), embossSpotLightIntensityValues.size(), embossSpecPowValues.size(),
    embossSpecIntensityValues.size() });

const std::array laserOutlineWidthValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array laserFrequencyValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array laserDirectionValues = { Vector2f { 0.0f, 0.0f }, Vector2f { 1.0f, 1.0f },
    Vector2f { 10.0f, 10.0f }, Vector2f { 50.0f, 50.0f } };
const std::array laserProgressValues = { 0.0f, 0.5f, 1.0f };
const std::array laserLightDirValues = { Vector2f { 0.0f, 0.0f }, Vector2f { 1.0f, 1.0f },
    Vector2f { 10.0f, 10.0f }, Vector2f { 50.0f, 50.0f } };
const std::array laserShadowColorValues = { Vector4f { 0.0f, 0.0f, 0.0f, 0.0f },
    Vector4f { 1.0f, 0.0f, 0.0f, 1.0f }, Vector4f { 1.0f, 1.0f, 1.0f, 1.0f } };
const std::array laserShadowRadiusValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const std::array laserShadowDistanceValues = { 0.0f, 1.0f, 10.0f, 50.0f };
const size_t LASER_COMBINATION_COUNT = std::max({ laserOutlineWidthValues.size(), laserFrequencyValues.size(),
    laserProgressValues.size(), laserShadowRadiusValues.size(), laserShadowDistanceValues.size() });

// the effect-kit chain applies the effect on the input image; the sticker field of the params is
// filled in by EffectImageChain::ApplyStickerEmboss/ApplyStickerLaserShader with the chain input
void InitStickerEmbossParams(const std::shared_ptr<Drawing::GEStickerEmbossFilterParams>& params)
{
    if (!params) {
        return;
    }
    params->outlineWidth = 1.0f;
    params->refractionRate = 1.0f;
    params->dirIntensity = 1.0f;
    params->edgeLightWidth = 1.0f;
    params->edgeLightFeatherRate = 1.0f;
    params->edgeLightIntensity = Vector2f(0.5f, 0.5f);
    params->spotLightCenter = Vector2f(0.5f, 0.5f);
    params->spotLightIntensity = 1.0f;
    params->specPow = 1.0f;
    params->specIntensity = 1.0f;
}

void InitStickerLaserParams(const std::shared_ptr<Drawing::GEStickerLaserShaderParams>& params)
{
    if (!params) {
        return;
    }
    params->outlineWidth = 2.0f;
    params->frequency = 0.005f;
    params->direction = Vector2f(1.0f, 0.0f);
    params->progress = 1.0f;
    params->lightDir = Vector2f(0.5f, 0.5f);
    params->elevationShadowColor = Vector4f(0.0f, 0.0f, 0.0f, 0.2f);
    params->elevationShadowRadius = 10.0f;
    params->shadowDistance = 10.0f;
}
} // namespace

class EffectImageStickerTest : public RSGraphicTest {
public:
    void BeforeEach() override
    {
        SetScreenSize(SCREEN_WIDTH, SCREEN_HEIGHT);
    }

    void DrawBackgroundNodePixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap, const Vector4f bounds)
    {
        if (pixelMap == nullptr) {
            return;
        }
        auto image = std::make_shared<RSImage>();
        image->SetPixelMap(pixelMap);
        image->SetImageFit(static_cast<int>(ImageFit::FILL));
        auto node = RSCanvasNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext());
        node->SetBounds(bounds);
        node->SetFrame(bounds);
        node->SetBgImageSize(bounds[BOUNDS_WIDTH_INDEX], bounds[BOUNDS_HEIGHT_INDEX]);
        node->SetBgImage(image);
        GetRootNode()->AddChild(node);
        RegisterNode(node);
    }

    void SetUpTestNodeWithRender(const size_t i, const size_t columnCount, const size_t rowCount,
        const std::shared_ptr<Media::PixelMap>& srcPixelMap,
        const std::vector<std::shared_ptr<EffectImageFilter>>& filters)
    {
        if (columnCount == 0 || rowCount == 0 || srcPixelMap == nullptr || filters.empty()) {
            return;
        }
        std::shared_ptr<Media::PixelMap> dstPixelMap = nullptr;
        EffectImageRender render;
        auto ret = render.Render(srcPixelMap, filters, false, dstPixelMap);
        EXPECT_EQ(ret, DrawingError::ERR_OK);
        const size_t sizeX = SCREEN_WIDTH / columnCount;
        const size_t sizeY = SCREEN_HEIGHT / rowCount;
        const size_t x = (i % columnCount) * sizeX;
        const size_t y = (i / columnCount) * sizeY;
        DrawBackgroundNodePixelMap(dstPixelMap, Vector4f(x, y, sizeX, sizeY));
    }

    void SetUpTestNodeWithRender(const size_t i, const size_t columnCount, const size_t rowCount,
        const std::shared_ptr<Media::PixelMap>& srcPixelMap,
        const std::shared_ptr<EffectImageFilter>& filter)
    {
        std::vector<std::shared_ptr<EffectImageFilter>> filters = { filter };
        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filters);
    }
};

/*
 * Test EffectImageFilter StickerEmboss OutlineWidth parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_OutlineWidth_Test)
{
    const size_t columnCount = embossOutlineWidthValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossOutlineWidthValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->outlineWidth = embossOutlineWidthValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss RefractionRate parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_RefractionRate_Test)
{
    const size_t columnCount = embossRefractionRateValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossRefractionRateValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->refractionRate = embossRefractionRateValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss DirIntensity parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_DirIntensity_Test)
{
    const size_t columnCount = embossDirIntensityValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossDirIntensityValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->dirIntensity = embossDirIntensityValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss EdgeLightWidth parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_EdgeLightWidth_Test)
{
    const size_t columnCount = embossEdgeLightWidthValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossEdgeLightWidthValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->edgeLightWidth = embossEdgeLightWidthValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss EdgeLightFeatherRate parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_EdgeLightFeatherRate_Test)
{
    const size_t columnCount = embossEdgeLightFeatherRateValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossEdgeLightFeatherRateValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->edgeLightFeatherRate = embossEdgeLightFeatherRateValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss EdgeLightIntensity parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_EdgeLightIntensity_Test)
{
    const size_t columnCount = embossEdgeLightIntensityValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossEdgeLightIntensityValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->edgeLightIntensity = embossEdgeLightIntensityValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss SpotLightCenter parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_SpotLightCenter_Test)
{
    const size_t columnCount = embossSpotLightCenterValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossSpotLightCenterValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->spotLightCenter = embossSpotLightCenterValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss SpotLightIntensity parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_SpotLightIntensity_Test)
{
    const size_t columnCount = embossSpotLightIntensityValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossSpotLightIntensityValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->spotLightIntensity = embossSpotLightIntensityValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss SpecPow parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_SpecPow_Test)
{
    const size_t columnCount = embossSpecPowValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossSpecPowValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->specPow = embossSpecPowValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss SpecIntensity parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_SpecIntensity_Test)
{
    const size_t columnCount = embossSpecIntensityValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < embossSpecIntensityValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->specIntensity = embossSpecIntensityValues[i];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss parameter combination
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_Combination_Test)
{
    const size_t columnCount = EMBOSS_COMBINATION_COUNT;
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < EMBOSS_COMBINATION_COUNT; i++) {
        auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
        InitStickerEmbossParams(params);
        params->outlineWidth = embossOutlineWidthValues[i % embossOutlineWidthValues.size()];
        params->refractionRate = embossRefractionRateValues[i % embossRefractionRateValues.size()];
        params->dirIntensity = embossDirIntensityValues[i % embossDirIntensityValues.size()];
        params->edgeLightWidth = embossEdgeLightWidthValues[i % embossEdgeLightWidthValues.size()];
        params->edgeLightFeatherRate = embossEdgeLightFeatherRateValues[i % embossEdgeLightFeatherRateValues.size()];
        params->edgeLightIntensity = embossEdgeLightIntensityValues[i % embossEdgeLightIntensityValues.size()];
        params->spotLightCenter = embossSpotLightCenterValues[i % embossSpotLightCenterValues.size()];
        params->spotLightIntensity = embossSpotLightIntensityValues[i % embossSpotLightIntensityValues.size()];
        params->specPow = embossSpecPowValues[i % embossSpecPowValues.size()];
        params->specIntensity = embossSpecIntensityValues[i % embossSpecIntensityValues.size()];
        auto filter = EffectImageFilter::StickerEmboss(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader OutlineWidth parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_OutlineWidth_Test)
{
    const size_t columnCount = laserOutlineWidthValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserOutlineWidthValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->outlineWidth = laserOutlineWidthValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader Frequency parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_Frequency_Test)
{
    const size_t columnCount = laserFrequencyValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserFrequencyValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->frequency = laserFrequencyValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader Direction parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_Direction_Test)
{
    const size_t columnCount = laserDirectionValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserDirectionValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->direction = laserDirectionValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader Progress parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_Progress_Test)
{
    const size_t columnCount = laserProgressValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserProgressValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->progress = laserProgressValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader LightDir parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_LightDir_Test)
{
    const size_t columnCount = laserLightDirValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserLightDirValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->lightDir = laserLightDirValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader ElevationShadowColor parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_ElevationShadowColor_Test)
{
    const size_t columnCount = laserShadowColorValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserShadowColorValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->elevationShadowColor = laserShadowColorValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader ElevationShadowRadius parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_ElevationShadowRadius_Test)
{
    const size_t columnCount = laserShadowRadiusValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserShadowRadiusValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->elevationShadowRadius = laserShadowRadiusValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader ShadowDistance parameter
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_ShadowDistance_Test)
{
    const size_t columnCount = laserShadowDistanceValues.size();
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < laserShadowDistanceValues.size(); i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->shadowDistance = laserShadowDistanceValues[i];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerLaserShader parameter combination
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_Combination_Test)
{
    const size_t columnCount = LASER_COMBINATION_COUNT;
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    for (size_t i = 0; i < LASER_COMBINATION_COUNT; i++) {
        auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
        InitStickerLaserParams(params);
        params->outlineWidth = laserOutlineWidthValues[i % laserOutlineWidthValues.size()];
        params->frequency = laserFrequencyValues[i % laserFrequencyValues.size()];
        params->direction = laserDirectionValues[i % laserDirectionValues.size()];
        params->progress = laserProgressValues[i % laserProgressValues.size()];
        params->lightDir = laserLightDirValues[i % laserLightDirValues.size()];
        params->elevationShadowColor = laserShadowColorValues[i % laserShadowColorValues.size()];
        params->elevationShadowRadius = laserShadowRadiusValues[i % laserShadowRadiusValues.size()];
        params->shadowDistance = laserShadowDistanceValues[i % laserShadowDistanceValues.size()];
        auto filter = EffectImageFilter::StickerLaserShader(params);

        SetUpTestNodeWithRender(i, columnCount, rowCount, srcPixelMap, filter);
    }
}

/*
 * Test EffectImageFilter StickerEmboss + StickerLaserShader cascade through the effect-kit chain
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerCascade_Test)
{
    const size_t columnCount = 2;
    const size_t rowCount = 1;
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);

    auto embossParams = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
    InitStickerEmbossParams(embossParams);
    auto laserParams = std::make_shared<Drawing::GEStickerLaserShaderParams>();
    InitStickerLaserParams(laserParams);

    std::vector<std::shared_ptr<EffectImageFilter>> filters;
    filters.push_back(EffectImageFilter::StickerEmboss(embossParams));
    filters.push_back(EffectImageFilter::StickerLaserShader(laserParams));

    SetUpTestNodeWithRender(0, columnCount, rowCount, srcPixelMap, filters);
}
/*
 * Test EffectImageFilter StickerEmboss rejects the CPU path
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_ForceCPU_Test)
{
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);
    auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
    InitStickerEmbossParams(params);
    std::vector<std::shared_ptr<EffectImageFilter>> filters = { EffectImageFilter::StickerEmboss(params) };
    std::shared_ptr<Media::PixelMap> dstPixelMap = nullptr;
    EffectImageRender render;
    auto ret = render.Render(srcPixelMap, filters, true, dstPixelMap);
    EXPECT_EQ(ret, DrawingError::ERR_ILLEGAL_INPUT);
}

/*
 * Test EffectImageFilter StickerLaserShader rejects the CPU path
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_ForceCPU_Test)
{
    auto srcPixelMap = DecodePixelMap(TEST_IMAGE_PATH, Media::AllocatorType::SHARE_MEM_ALLOC);
    auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
    InitStickerLaserParams(params);
    std::vector<std::shared_ptr<EffectImageFilter>> filters = { EffectImageFilter::StickerLaserShader(params) };
    std::shared_ptr<Media::PixelMap> dstPixelMap = nullptr;
    EffectImageRender render;
    auto ret = render.Render(srcPixelMap, filters, true, dstPixelMap);
    EXPECT_EQ(ret, DrawingError::ERR_ILLEGAL_INPUT);
}

/*
 * Test EffectImageChain ApplyStickerEmboss fails without Prepare
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerEmboss_NotPrepared_Test)
{
    auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
    InitStickerEmbossParams(params);
    EffectImageChain imageChain;
    auto ret = imageChain.ApplyStickerEmboss(params);
    EXPECT_EQ(ret, DrawingError::ERR_NOT_PREPARED);
}

/*
 * Test EffectImageChain ApplyStickerLaserShader fails without Prepare
 */
GRAPHIC_TEST(EffectImageStickerTest, EFFECT_TEST, Set_EffectImage_StickerLaserShader_NotPrepared_Test)
{
    auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
    InitStickerLaserParams(params);
    EffectImageChain imageChain;
    auto ret = imageChain.ApplyStickerLaserShader(params);
    EXPECT_EQ(ret, DrawingError::ERR_NOT_PREPARED);
}
} // namespace OHOS::Rosen
