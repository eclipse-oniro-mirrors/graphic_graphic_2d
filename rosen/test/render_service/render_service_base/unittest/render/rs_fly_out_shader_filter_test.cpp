/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "render/rs_fly_out_shader_filter.h"
#include "draw/color.h"
#include "image/image_info.h"
#include "skia_image.h"
#include "skia_image_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class RSFlyOutShaderFilterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSFlyOutShaderFilterTest::SetUpTestCase() {}
void RSFlyOutShaderFilterTest::TearDownTestCase() {}
void RSFlyOutShaderFilterTest::SetUp() {}
void RSFlyOutShaderFilterTest::TearDown() {}

/**
 * @tc.name: DrawImageRect001
 * @tc.desc: test results of DrawImageRect
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect001, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    // if image == nullptr
    std::shared_ptr<Drawing::Image> image = nullptr;
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_FALSE(image);

    effectFilter.degree_ = 1.0f;
    image = std::make_shared<Drawing::Image>();
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image);
}

/**
 * @tc.name: DrawImageRect002
 * @tc.desc: test results of DrawImageRect
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect002, TestSize.Level1)
{
    // if FLY_OUT_MODE
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::ImageInfo imageInfo(1, 1, Drawing::ColorType::COLORTYPE_ALPHA_8, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth());
    EXPECT_TRUE(image->GetHeight());

    // if FLY_IN_MODE
    effectFilter.flyMode_ = 1;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth());
    EXPECT_TRUE(image->GetHeight());
}

/**
 * @tc.name: DrawImageRect003
 * @tc.desc: test results of DrawImageRect
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect003, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetWidth() <= 0
    Drawing::ImageInfo imageInfo(0, 1, Drawing::ColorType::COLORTYPE_ALPHA_8, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect004
 * @tc.desc: test results of DrawImageRect
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect004, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_ALPHA_8, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect406
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_F16, AlphaType is ALPHATYPE_OPAQUE
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect406, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_F16, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4061
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_F16, AlphaType is ALPHATYPE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4061, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_F16, Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4062
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_F16, AlphaType is ALPHATYPE_PREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4062, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_F16, Drawing::AlphaType::ALPHATYPE_PREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4063
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_F16, AlphaType is ALPHATYPE_UNPREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4063, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_F16, Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect407
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_N32, AlphaType is ALPHATYPE_OPAQUE
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect407, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_N32, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4071
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_N32, AlphaType is ALPHATYPE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4071, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_N32, Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4072
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_N32, AlphaType is ALPHATYPE_PREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4072, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_N32, Drawing::AlphaType::ALPHATYPE_PREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4073
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_N32, AlphaType is ALPHATYPE_UNPREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4073, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_N32, Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect408
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_1010102, AlphaType is ALPHATYPE_OPAQUE
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect408, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_1010102, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4081
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_1010102, AlphaType is ALPHATYPE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4081, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_1010102, Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4082
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_1010102, AlphaType is ALPHATYPE_PREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4082, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_1010102, Drawing::AlphaType::ALPHATYPE_PREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4083
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGBA_1010102, AlphaType is ALPHATYPE_UNPREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4083, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGBA_1010102, Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect409
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_GRAY_8, AlphaType is ALPHATYPE_OPAQUE
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect409, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_GRAY_8, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4091
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_GRAY_8, AlphaType is ALPHATYPE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4091, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_GRAY_8, Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4092
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_GRAY_8, AlphaType is ALPHATYPE_PREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4092, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_GRAY_8, Drawing::AlphaType::ALPHATYPE_PREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4093
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_GRAY_8, AlphaType is ALPHATYPE_UNPREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4093, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_GRAY_8, Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect410
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGB_888X, AlphaType is ALPHATYPE_OPAQUE
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect410, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGB_888X, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4101
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGB_888X, AlphaType is ALPHATYPE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4101, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGB_888X, Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4102
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGB_888X, AlphaType is ALPHATYPE_PREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4102, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGB_888X, Drawing::AlphaType::ALPHATYPE_PREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: DrawImageRect4103
 * @tc.desc: test results of DrawImageRect,ColorType is COLORTYPE_RGB_888X, AlphaType is ALPHATYPE_UNPREMUL
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, DrawImageRect4103, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    Drawing::Canvas canvas;
    std::shared_ptr<Drawing::Image> image;
    image = std::make_shared<Drawing::Image>();
    // 1.0f, 1.0f, 2.0f, 2.0f is left top right bottom
    Drawing::Rect src { 1.0f, 1.0f, 2.0f, 2.0f };
    Drawing::Rect dst { 1.0f, 1.0f, 2.0f, 2.0f };
    // if image->GetHeight() <= 0
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_RGB_888X, Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    effectFilter.DrawImageRect(canvas, image, src, dst);
    EXPECT_TRUE(image->GetWidth() == 0);
    EXPECT_TRUE(image->GetHeight() == 0);
}

/**
 * @tc.name: GetFunc001
 * @tc.desc: test getFunc
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, GetFunc001, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.5f, 1);
    uint32_t flyMode = effectFilter.GetFlyMode();
    EXPECT_TRUE(flyMode == 1);

    float degree = effectFilter.GetDegree();
    EXPECT_FLOAT_EQ(degree, 0.5f);

    std::string description = effectFilter.GetDescription();
    std::string result = "RSFlyOutShaderFilter " + std::to_string(effectFilter.degree_);
    EXPECT_TRUE(description == result);
}

/**
 * @tc.name: GetBrush001
 * @tc.desc: test getFunc
 * @tc.type: FUNC
 * @tc.require: issueIAH2TY
 */
HWTEST_F(RSFlyOutShaderFilterTest, GetBrush001, TestSize.Level1)
{
    RSFlyOutShaderFilter effectFilter(0.f, 0);
    // if image == nullptr
    std::shared_ptr<Drawing::Image> image = nullptr;
    auto brush = effectFilter.GetBrush(image);
    EXPECT_FALSE(brush.GetShaderEffect());

    image = std::make_shared<Drawing::Image>();
    Drawing::ImageInfo imageInfo(1, 0, Drawing::ColorType::COLORTYPE_ALPHA_8, Drawing::AlphaType::ALPHATYPE_OPAQUE);
    auto skImageInfo = Drawing::SkiaImageInfo::ConvertToSkImageInfo(imageInfo);
    int addr1 = 1;
    int* addr = &addr1;
    auto skiaPixmap = SkPixmap(skImageInfo, addr, 1);
    Drawing::ReleaseContext releaseContext = nullptr;
    Drawing::RasterReleaseProc rasterReleaseProc = nullptr;
    sk_sp<SkImage> skImage = SkImage::MakeFromRaster(skiaPixmap, rasterReleaseProc, releaseContext);
    auto skiaImage = std::make_shared<Drawing::SkiaImage>(skImage);
    image->imageImplPtr = skiaImage;
    brush = effectFilter.GetBrush(image);
    EXPECT_TRUE(brush.GetShaderEffect());
}
} // namespace Rosen
} // namespace OHOS
