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
#include <memory>

#include "effect_image_chain.h"
#include "effect_image_render.h"
#include "pixel_map.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

namespace {
std::shared_ptr<Media::PixelMap> MakePixelMap(int32_t width = 8, int32_t height = 8)
{
    Media::InitializationOptions opts;
    opts.size = { width, height };
    return std::shared_ptr<Media::PixelMap>(Media::PixelMap::Create(opts));
}

std::shared_ptr<Drawing::GEStickerEmbossFilterParams> MakeEmbossParams()
{
    auto params = std::make_shared<Drawing::GEStickerEmbossFilterParams>();
    params->outlineWidth = 2.0f;
    params->refractionRate = 1.0f;
    params->dirIntensity = 1.0f;
    params->edgeLightWidth = 1.0f;
    params->edgeLightFeatherRate = 1.0f;
    params->edgeLightIntensity = Vector2f(0.5f, 0.5f);
    params->spotLightCenter = Vector2f(0.5f, 0.5f);
    params->spotLightIntensity = 1.0f;
    params->specPow = 1.0f;
    params->specIntensity = 1.0f;
    return params;
}

std::shared_ptr<Drawing::GEStickerLaserShaderParams> MakeLaserParams()
{
    auto params = std::make_shared<Drawing::GEStickerLaserShaderParams>();
    params->outlineWidth = 2.0f;
    params->frequency = 0.005f;
    params->progress = 1.0f;
    params->direction = Vector2f(1.0f, 0.0f);
    params->lightDir = Vector2f(0.5f, 0.5f);
    params->elevationShadowColor = Vector4f(0.0f, 0.0f, 0.0f, 0.2f);
    params->elevationShadowRadius = 10.0f;
    params->shadowDistance = 10.0f;
    return params;
}
} // namespace

class EffectImageStickerUnittest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name: StickerEmbossMethod
 * @tc.desc: Verify the StickerEmboss factory wires the params into an EffectImageStickerEmbossFilter
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossMethod, TestSize.Level1)
{
    auto params = MakeEmbossParams();
    auto filter = EffectImageFilter::StickerEmboss(params);
    ASSERT_NE(filter, nullptr);
    auto embossFilter = std::static_pointer_cast<EffectImageStickerEmbossFilter>(filter);
    ASSERT_NE(embossFilter, nullptr);
    EXPECT_EQ(embossFilter->stickerEmbossData_, params);
}

/**
 * @tc.name: StickerLaserShaderMethod
 * @tc.desc: Verify the StickerLaserShader factory wires the params into an EffectImageStickerLaserShaderFilter
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderMethod, TestSize.Level1)
{
    auto params = MakeLaserParams();
    auto filter = EffectImageFilter::StickerLaserShader(params);
    ASSERT_NE(filter, nullptr);
    auto laserFilter = std::static_pointer_cast<EffectImageStickerLaserShaderFilter>(filter);
    ASSERT_NE(laserFilter, nullptr);
    EXPECT_EQ(laserFilter->stickerLaserData_, params);
}

/**
 * @tc.name: ApplyStickerEmbossMethod
 * @tc.desc: Verify the emboss filter entry reaches the effect stage on a prepared chain
 */
HWTEST_F(EffectImageStickerUnittest, ApplyStickerEmbossMethod, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    auto chain = std::make_shared<EffectImageChain>();
    ASSERT_EQ(chain->Prepare(pixelMap, false), DrawingError::ERR_OK);

    auto filter = EffectImageFilter::StickerEmboss(MakeEmbossParams());
    ASSERT_NE(filter, nullptr);
    auto ret = filter->Apply(chain);
    // The main path is reached (no crash, not blocked by the prepared/image guards)
    EXPECT_NE(ret, DrawingError::ERR_NOT_PREPARED);
    EXPECT_NE(ret, DrawingError::ERR_IMAGE_NULL);
}

/**
 * @tc.name: ApplyStickerEmbossMethodImageNull
 * @tc.desc: Verify Apply rejects a null chain with ERR_IMAGE_NULL
 */
HWTEST_F(EffectImageStickerUnittest, ApplyStickerEmbossMethodImageNull, TestSize.Level1)
{
    auto filter = EffectImageFilter::StickerEmboss(MakeEmbossParams());
    ASSERT_NE(filter, nullptr);
    EXPECT_EQ(filter->Apply(nullptr), DrawingError::ERR_IMAGE_NULL);
}

/**
 * @tc.name: ApplyStickerLaserShaderMethod
 * @tc.desc: Verify the laser filter entry reaches the effect stage on a prepared chain
 */
HWTEST_F(EffectImageStickerUnittest, ApplyStickerLaserShaderMethod, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    auto chain = std::make_shared<EffectImageChain>();
    ASSERT_EQ(chain->Prepare(pixelMap, false), DrawingError::ERR_OK);

    auto filter = EffectImageFilter::StickerLaserShader(MakeLaserParams());
    ASSERT_NE(filter, nullptr);
    auto ret = filter->Apply(chain);
    EXPECT_NE(ret, DrawingError::ERR_NOT_PREPARED);
    EXPECT_NE(ret, DrawingError::ERR_IMAGE_NULL);
}

/**
 * @tc.name: ApplyStickerLaserShaderMethodImageNull
 * @tc.desc: Verify the laser Apply rejects a null chain with ERR_IMAGE_NULL
 */
HWTEST_F(EffectImageStickerUnittest, ApplyStickerLaserShaderMethodImageNull, TestSize.Level1)
{
    auto filter = EffectImageFilter::StickerLaserShader(MakeLaserParams());
    ASSERT_NE(filter, nullptr);
    EXPECT_EQ(filter->Apply(nullptr), DrawingError::ERR_IMAGE_NULL);
}

/**
 * @tc.name: StickerEmbossReturnsErrorWhenNotPrepared
 * @tc.desc: Verify ApplyStickerEmboss without Prepare returns ERR_NOT_PREPARED
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossReturnsErrorWhenNotPrepared, TestSize.Level1)
{
    EffectImageChain chain;
    auto ret = chain.ApplyStickerEmboss(MakeEmbossParams());
    EXPECT_EQ(ret, DrawingError::ERR_NOT_PREPARED);
}

/**
 * @tc.name: StickerEmbossReturnsErrorWhenForceCPU
 * @tc.desc: Verify ApplyStickerEmboss rejects the CPU path with ERR_ILLEGAL_INPUT
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossReturnsErrorWhenForceCPU, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, true), DrawingError::ERR_OK);
    auto ret = chain.ApplyStickerEmboss(MakeEmbossParams());
    EXPECT_EQ(ret, DrawingError::ERR_ILLEGAL_INPUT);
}

/**
 * @tc.name: StickerEmbossReturnsErrorWhenImageNull
 * @tc.desc: Verify ApplyStickerEmboss returns ERR_IMAGE_NULL when the internal image is missing
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossReturnsErrorWhenImageNull, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);
    chain.image_ = nullptr;
    auto ret = chain.ApplyStickerEmboss(MakeEmbossParams());
    EXPECT_EQ(ret, DrawingError::ERR_IMAGE_NULL);
}

/**
 * @tc.name: StickerEmbossWithPreparedChain
 * @tc.desc: Verify ApplyStickerEmboss on a prepared chain reaches the effect generation stage
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossWithPreparedChain, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);

    auto params = MakeEmbossParams();
    auto ret = chain.ApplyStickerEmboss(params);
    // Reached the generation stage: either composed (ERR_OK) or generation failed (ERR_ILLEGAL_INPUT)
    EXPECT_TRUE(ret == DrawingError::ERR_OK || ret == DrawingError::ERR_ILLEGAL_INPUT);
    // The chain input image is injected as the sticker whose contour is extracted
    EXPECT_NE(params->sticker, nullptr);
}

/**
 * @tc.name: StickerLaserShaderReturnsErrorWhenNotPrepared
 * @tc.desc: Verify ApplyStickerLaserShader without Prepare returns ERR_NOT_PREPARED
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderReturnsErrorWhenNotPrepared, TestSize.Level1)
{
    EffectImageChain chain;
    auto ret = chain.ApplyStickerLaserShader(MakeLaserParams());
    EXPECT_EQ(ret, DrawingError::ERR_NOT_PREPARED);
}

/**
 * @tc.name: StickerLaserShaderReturnsErrorWhenForceCPU
 * @tc.desc: Verify ApplyStickerLaserShader rejects the CPU path with ERR_ILLEGAL_INPUT
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderReturnsErrorWhenForceCPU, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, true), DrawingError::ERR_OK);
    auto ret = chain.ApplyStickerLaserShader(MakeLaserParams());
    EXPECT_EQ(ret, DrawingError::ERR_ILLEGAL_INPUT);
}

/**
 * @tc.name: StickerLaserShaderReturnsErrorWhenImageNull
 * @tc.desc: Verify ApplyStickerLaserShader returns ERR_IMAGE_NULL when the internal image is missing
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderReturnsErrorWhenImageNull, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);
    chain.image_ = nullptr;
    auto ret = chain.ApplyStickerLaserShader(MakeLaserParams());
    EXPECT_EQ(ret, DrawingError::ERR_IMAGE_NULL);
}

/**
 * @tc.name: StickerLaserShaderWithPreparedChain
 * @tc.desc: Verify ApplyStickerLaserShader on a prepared chain reaches the effect generation stage
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderWithPreparedChain, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);

    auto params = MakeLaserParams();
    auto ret = chain.ApplyStickerLaserShader(params);
    EXPECT_TRUE(ret == DrawingError::ERR_OK || ret == DrawingError::ERR_ILLEGAL_INPUT);
    EXPECT_NE(params->sticker, nullptr);
}

/**
 * @tc.name: StickerEmbossReturnsErrorWhenDataNull
 * @tc.desc: Verify null emboss data is rejected by the guard chain without processing
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossReturnsErrorWhenDataNull, TestSize.Level1)
{
    // The not-prepared guard rejects the call before the data is dereferenced
    EffectImageChain chain;
    auto ret = chain.ApplyStickerEmboss(nullptr);
    EXPECT_EQ(ret, DrawingError::ERR_NOT_PREPARED);
}

/**
 * @tc.name: StickerLaserShaderReturnsErrorWhenDataNull
 * @tc.desc: Verify null laser data is rejected by the guard chain without processing
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderReturnsErrorWhenDataNull, TestSize.Level1)
{
    // The not-prepared guard rejects the call before the data is dereferenced
    EffectImageChain chain;
    auto ret = chain.ApplyStickerLaserShader(nullptr);
    EXPECT_EQ(ret, DrawingError::ERR_NOT_PREPARED);
}

/**
 * @tc.name: StickerEmbossWithPendingFilters
 * @tc.desc: Verify ApplyStickerEmboss consumes pending filters first and snapshots the image into the sticker
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossWithPendingFilters, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);

    auto blurFilter = Drawing::ImageFilter::CreateBlurImageFilter(1, 1, Drawing::TileMode::DECAL, nullptr);
    ASSERT_NE(blurFilter, nullptr);
    ASSERT_EQ(chain.ApplyDrawingFilter(blurFilter), DrawingError::ERR_OK);
    ASSERT_NE(chain.filters_, nullptr);

    auto params = MakeEmbossParams();
    auto snapshot = chain.image_;
    auto ret = chain.ApplyStickerEmboss(params);
    EXPECT_TRUE(ret == DrawingError::ERR_OK || ret == DrawingError::ERR_ILLEGAL_INPUT);
    // UpdateImage consumed the pending drawing filter
    EXPECT_EQ(chain.filters_, nullptr);
    // The blurred snapshot became the sticker the emboss effect extracts
    EXPECT_EQ(params->sticker, snapshot);
}

/**
 * @tc.name: StickerLaserShaderWithPendingFilters
 * @tc.desc: Verify ApplyStickerLaserShader consumes pending filters first and snapshots the image into the sticker
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderWithPendingFilters, TestSize.Level1)
{
    auto pixelMap = MakePixelMap();
    ASSERT_NE(pixelMap, nullptr);
    EffectImageChain chain;
    ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);

    auto blurFilter = Drawing::ImageFilter::CreateBlurImageFilter(1, 1, Drawing::TileMode::DECAL, nullptr);
    ASSERT_NE(blurFilter, nullptr);
    ASSERT_EQ(chain.ApplyDrawingFilter(blurFilter), DrawingError::ERR_OK);
    ASSERT_NE(chain.filters_, nullptr);

    auto params = MakeLaserParams();
    auto snapshot = chain.image_;
    auto ret = chain.ApplyStickerLaserShader(params);
    EXPECT_TRUE(ret == DrawingError::ERR_OK || ret == DrawingError::ERR_ILLEGAL_INPUT);
    EXPECT_EQ(chain.filters_, nullptr);
    EXPECT_EQ(params->sticker, snapshot);
}

/**
 * @tc.name: StickerEmbossSweepsOutlineWidth
 * @tc.desc: Swept-parameter emboss smoke migrated from graphic_test; the effect stage is
 *           reached for every outline width without crashing or tripping the basic guards
 */
HWTEST_F(EffectImageStickerUnittest, StickerEmbossSweepsOutlineWidth, TestSize.Level1)
{
    for (float outlineWidth : { 0.0f, 1.0f, 10.0f, 50.0f }) {
        auto pixelMap = MakePixelMap();
        ASSERT_NE(pixelMap, nullptr);
        EffectImageChain chain;
        ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);

        auto params = MakeEmbossParams();
        params->outlineWidth = outlineWidth;
        auto ret = chain.ApplyStickerEmboss(params);
        // The main path is reached (no crash, not blocked by the prepared/image guards)
        EXPECT_NE(ret, DrawingError::ERR_NOT_PREPARED);
        EXPECT_NE(ret, DrawingError::ERR_IMAGE_NULL);
    }
}

/**
 * @tc.name: StickerLaserShaderSweepsFrequencyAndProgress
 * @tc.desc: Swept-parameter laser smoke migrated from graphic_test; the effect stage is
 *           reached for every frequency/progress combination without crashing
 */
HWTEST_F(EffectImageStickerUnittest, StickerLaserShaderSweepsFrequencyAndProgress, TestSize.Level1)
{
    const float frequencies[] = { 0.0f, 1.0f, 10.0f, 50.0f };
    const float progresses[] = { 0.0f, 0.5f, 1.0f };
    for (float frequency : frequencies) {
        for (float progress : progresses) {
            auto pixelMap = MakePixelMap();
            ASSERT_NE(pixelMap, nullptr);
            EffectImageChain chain;
            ASSERT_EQ(chain.Prepare(pixelMap, false), DrawingError::ERR_OK);

            auto params = MakeLaserParams();
            params->frequency = frequency;
            params->progress = progress;
            auto ret = chain.ApplyStickerLaserShader(params);
            EXPECT_NE(ret, DrawingError::ERR_NOT_PREPARED);
            EXPECT_NE(ret, DrawingError::ERR_IMAGE_NULL);
        }
    }
}

} // namespace Rosen
} // namespace OHOS
