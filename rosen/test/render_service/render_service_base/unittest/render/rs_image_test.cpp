/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "message_parcel.h"
#include "pixel_map.h"
#include "skia_canvas.h"

#include "draw/surface.h"
#include "render/rs_image.h"
#include "render/rs_image_cache.h"
#include "transaction/rs_marshalling_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSImageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSImageTest::SetUpTestCase() {}
void RSImageTest::TearDownTestCase() {}
void RSImageTest::SetUp() {}
void RSImageTest::TearDown() {}

/**
 * @tc.name: IsEqual001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, IsEqual001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSMask by Gradient
     */
    RSImage rsImage;
    int res = rsImage.IsEqual(rsImage);
    ASSERT_TRUE(res);
    RSImage other;
    other.SetScale(2.f);
    res = rsImage.IsEqual(other);
    ASSERT_FALSE(res);
}

static std::shared_ptr<Media::PixelMap> CreatePixelMap(int width, int height)
{
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    auto pixelmap = Media::PixelMap::Create(opts);
    auto address = const_cast<uint32_t*>(pixelmap->GetPixel32(0, 0));
    if (address == nullptr) {
        return nullptr;
    }
    Drawing::ImageInfo info = Drawing::ImageInfo(
        pixelmap->GetWidth(), pixelmap->GetHeight(), Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL);
    auto surface = Drawing::Surface::MakeRasterDirect(info, address, pixelmap->GetRowBytes());
    auto canvas = surface->GetCanvas();
    canvas->Clear(Drawing::Color::COLOR_YELLOW);
    Drawing::Brush brush;
    brush.SetColor(Drawing::Color::COLOR_RED);
    canvas->AttachBrush(brush);
    canvas->DrawRect(Drawing::Rect(width / 4, height / 4, width / 2, height / 2));
    canvas->DetachBrush();
    return pixelmap;
}

/**
 * @tc.name: LifeCycle001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, LifeCycle001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSMask by Gradient
     */
    RSImage rsImage;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    float fLeft = 1.0f;
    float ftop = 1.0f;
    float fRight = 1.0f;
    float fBottom = 1.0f;
    rsImage.SetImageFit(0);
    Drawing::Rect rect { fLeft, ftop, fRight, fBottom };
    Drawing::Brush brush;
    std::shared_ptr<Media::PixelMap> pixelmap;
    rsImage.SetPixelMap(pixelmap);
    int width = 200;
    int height = 300;
    pixelmap = CreatePixelMap(width, height);
    rsImage.SetPixelMap(pixelmap);
    canvas.AttachBrush(brush);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), false);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(1);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(2);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(3);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(4);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(5);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(6);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(0);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    rsImage.SetImageFit(8);
    rsImage.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), true);
    canvas.DetachBrush();
}

/**
 * @tc.name: CanvasDrawImageTest
 * @tc.desc: test results of CanvasDrawImage
 * @tc.type: FUNC
 * @tc.require: issuesI9TOXM
 */
HWTEST_F(RSImageTest, CanvasDrawImageTest, TestSize.Level1)
{
    RSImage rsImage;
    Drawing::Canvas canvas;
    canvas.recordingState_ = true;
    Drawing::Rect rect { 1.0f, 1.0f, 1.0f, 1.0f };
    Drawing::Brush brush;
    // for test
    std::shared_ptr<Media::PixelMap> pixelmap = CreatePixelMap(200, 300);
    Drawing::SamplingOptions samplingOptions;
    rsImage.pixelMap_ = pixelmap;
    rsImage.pixelMap_->SetAstc(true);
    rsImage.image_ = std::make_shared<Drawing::Image>();
    rsImage.CanvasDrawImage(canvas, rect, samplingOptions, false);
    // for test
    rsImage.innerRect_ = Drawing::RectI { 0, 0, 10, 10 };
    rsImage.CanvasDrawImage(canvas, rect, samplingOptions, false);
}

/**
 * @tc.name: ApplyImageFitTest001
 * @tc.desc: Verify function ApplyImageFit
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, ApplyImageFitTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    RectF srcRf(0.f, 0.f, 0.f, 0.f);
    image->srcRect_ = srcRf;
    image->imageFit_ = ImageFit::TOP_LEFT;
    image->ApplyImageFit();
    EXPECT_EQ(image->srcRect_.width_, 0);
    RectF srcRs(1.f, 1.f, 1.f, 1.f);
    image->srcRect_ = srcRs;
    image->ApplyImageFit();
    EXPECT_EQ(image->srcRect_.width_, 1);
    image->scale_ = 0;
    image->imageFit_ = ImageFit::NONE;
    image->ApplyImageFit();
    image->imageFit_ = ImageFit::FIT_WIDTH;
    image->ApplyImageFit();
    image->imageFit_ = ImageFit::FIT_HEIGHT;
    image->ApplyImageFit();
    image->imageFit_ = ImageFit::SCALE_DOWN;
    image->ApplyImageFit();
    EXPECT_EQ(image->srcRect_.width_, 1);
}

/**
 * @tc.name: GetAdaptiveImageInfoWithFrameRectTest001
 * @tc.desc: Verify function GetAdaptiveImageInfoWithFrameRect
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, GetAdaptiveImageInfoWithFrameRectTest001, TestSize.Level1)
{
    Drawing::Rect frameRect;
    auto image = std::make_shared<RSImage>();
    image->imageFit_ = ImageFit::COVER;
    EXPECT_EQ(
        image->GetAdaptiveImageInfoWithCustomizedFrameRect(frameRect).fitNum, static_cast<int32_t>(ImageFit::COVER));
}

/**
 * @tc.name: GetImageFitTest001
 * @tc.desc: Verify function GetImageFit
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, GetImageFitTest001, TestSize.Level1)
{
    Drawing::Rect frameRect;
    auto image = std::make_shared<RSImage>();
    image->imageFit_ = ImageFit::COVER;
    EXPECT_EQ(image->GetImageFit(), ImageFit::COVER);
}

/**
 * @tc.name: SetFrameRectTest001
 * @tc.desc: Verify function SetFrameRect
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, SetFrameRectTest001, TestSize.Level1)
{
    float left = 0.f;
    float top = 0.f;
    float width = 1.0f;
    float height = 1.0f;
    RectF destRect(left, top, width, height);
    auto image = std::make_shared<RSImage>();
    image->SetFrameRect(destRect);
    EXPECT_EQ(image->frameRect_, destRect);
}

/**
 * @tc.name: ApplyCanvasClipTest001
 * @tc.desc: Verify function ApplyCanvasClip
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, ApplyCanvasClipTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    Drawing::Canvas canvas;
    image->ApplyCanvasClip(canvas);
    EXPECT_FALSE(image->hasRadius_);
    image->hasRadius_ = true;
    image->ApplyCanvasClip(canvas);
    EXPECT_TRUE(image->hasRadius_);
}

/**
 * @tc.name: UploadGpuTest001
 * @tc.desc: Verify function UploadGpu
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, UploadGpuTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    Drawing::Canvas canvas = RSPaintFilterCanvas(std::make_shared<Drawing::Canvas>().get());
    canvas.gpuContext_ = std::make_shared<Drawing::GPUContext>();
    image->UploadGpu(canvas);
    image->isYUVImage_ = true;
    image->UploadGpu(canvas);
    image->compressData_ = std::make_shared<Drawing::Data>();
    image->pixelMap_ = CreatePixelMap(200, 300);
    image->UploadGpu(canvas);
    EXPECT_EQ(image->compressData_, nullptr);
}

/**
 * @tc.name: DrawImageRepeatRectTest001
 * @tc.desc: Verify function DrawImageRepeatRect
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, DrawImageRepeatRectTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    Drawing::SamplingOptions samplingOptions;
    Drawing::Canvas canvas;
    canvas.impl_ = std::make_shared<Drawing::SkiaCanvas>();
    image->DrawImageRepeatRect(samplingOptions, canvas);
    image->pixelMap_ = std::make_shared<Media::PixelMap>();
    image->pixelMap_->SetAstc(true);
    image->imageRepeat_ = ImageRepeat::REPEAT_X;
    image->image_ = std::make_shared<Drawing::Image>();
    image->DrawImageRepeatRect(samplingOptions, canvas);
    image->innerRect_ = Drawing::RectI { 0, 0, 10, 10 };
    image->DrawImageRepeatRect(samplingOptions, canvas);
    EXPECT_EQ(image->frameRect_.left_, 0);
}

/**
 * @tc.name: SetCompressDataTest001
 * @tc.desc: Verify function SetCompressData
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, SetCompressDataTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    auto data = std::make_shared<Drawing::Data>();
    image->SetCompressData(data, 1, 1, 1);
    EXPECT_NE(image->compressData_, nullptr);
}

/**
 * @tc.name: SetCompressDataTest002
 * @tc.desc: Verify function SetCompressData
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, SetCompressDataTest002, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    auto data = std::make_shared<Drawing::Data>();
    image->SetCompressData(data);
    EXPECT_NE(image->compressData_, nullptr);
}

/**
 * @tc.name: SetRadiusTest001
 * @tc.desc: Verify function SetRadius
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, SetRadiusTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    std::vector<Drawing::Point> radius = { Drawing::Point { 1.f, 1.f }, Drawing::Point { 1.f, 1.f },
        Drawing::Point { 1.f, 1.f }, Drawing::Point { 1.f, 1.f } };
    image->SetRadius(radius);
    EXPECT_TRUE(image->hasRadius_);
}

/**
 * @tc.name: SetScaleTest001
 * @tc.desc: Verify function SetScale
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, SetScaleTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    image->SetScale(-1.0);
    image->SetScale(1.0);
    EXPECT_EQ(image->scale_, 1.0);
}

/**
 * @tc.name: SetNodeIdTest001
 * @tc.desc: Verify function SetNodeId
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, SetNodeIdTest001, TestSize.Level1)
{
    auto image = std::make_shared<RSImage>();
    image->SetNodeId(1);
    EXPECT_EQ(image->nodeId_, 1);
}

/**
 * @tc.name: LifeCycle002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSImageTest, LifeCycle002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSMask by Gradient
     */
    Parcel parcel;
    ASSERT_TRUE(RSImage::Unmarshalling(parcel) == nullptr);
    parcel.WriteInt32(1);
    ASSERT_TRUE(RSImage::Unmarshalling(parcel) == nullptr);
}

/**
 * @tc.name: TestRSImage001
 * @tc.desc: IsEqual test.
 * @tc.type: FUNC
 */
HWTEST_F(RSImageTest, TestRSImage001, TestSize.Level1)
{
    RSImage image;
    RSImage other;
    image.IsEqual(other);
}

/**
 * @tc.name: TestRSImage002
 * @tc.desc: CanvasDrawImage test.
 * @tc.type: FUNC
 */
HWTEST_F(RSImageTest, TestRSImage002, TestSize.Level1)
{
    RSImage image;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    Drawing::Rect rect;
    Drawing::Brush brush;
    bool isBackground = false;
    canvas.AttachBrush(brush);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    isBackground = true;
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    canvas.DetachBrush();
}

/**
 * @tc.name: TestRSImage003
 * @tc.desc: ApplyImageFit test.
 * @tc.type: FUNC
 */
HWTEST_F(RSImageTest, TestRSImage003, TestSize.Level1)
{
    RSImage image;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    Drawing::Rect rect;
    Drawing::Brush brush;
    bool isBackground = false;
    image.SetImageFit(0);
    canvas.AttachBrush(brush);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(5);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(2);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(3);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(4);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(6);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(1);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(7);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    image.SetImageFit(8);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions(), isBackground);
    canvas.DetachBrush();
}

/**
 * @tc.name: TestRSImage004
 * @tc.desc: SetImageRepeat test.
 * @tc.type: FUNC
 */
HWTEST_F(RSImageTest, TestRSImage004, TestSize.Level1)
{
    RSImage image;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    Drawing::Rect rect = Drawing::Rect(0, 0, 100, 100);
    RectF dstRect(10, 10, 80, 80);
    Drawing::Brush brush;
    image.SetDstRect(dstRect);
    image.SetImageRepeat(1);
    canvas.AttachBrush(brush);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions());
    image.SetImageRepeat(2);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions());
    image.SetImageRepeat(3);
    image.CanvasDrawImage(canvas, rect, Drawing::SamplingOptions());
    canvas.DetachBrush();
}

/**
 * @tc.name: RSImageBase001
 * @tc.desc: RSImageBase test.
 * @tc.type: FUNC
 */
HWTEST_F(RSImageTest, RSImageBase001, TestSize.Level1)
{
    RSImageBase imageBase;
    RectF rect(0, 0, 100, 100);
    imageBase.SetSrcRect(rect);
    imageBase.SetDstRect(rect);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    Drawing::Brush brush;
    canvas.AttachBrush(brush);
    imageBase.DrawImage(canvas, Drawing::SamplingOptions());
    canvas.DetachBrush();
#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    auto img = std::make_shared<Drawing::Image>();
    imageBase.SetDmaImage(img);
#endif

#ifdef ROSEN_OHOS
    Parcel parcel;
    EXPECT_FALSE(imageBase.Marshalling(parcel));
    EXPECT_EQ(imageBase.Unmarshalling(parcel), nullptr);
#endif
}

/**
 * @tc.name: RSImageCache001
 * @tc.desc: RSImageBase test.
 * @tc.type: FUNC
 */
HWTEST_F(RSImageTest, RSImageCache001, TestSize.Level1)
{
    auto rsImage = std::make_shared<RSImage>();
    std::shared_ptr<Media::PixelMap> pixelMap;
    int width = 200;
    int height = 300;
    pixelMap = CreatePixelMap(width, height);
    rsImage->SetPixelMap(pixelMap);

    MessageParcel parcel;
    EXPECT_EQ(RSMarshallingHelper::Marshalling(parcel, rsImage), true);
    std::shared_ptr<RSImage> newImage;
    EXPECT_EQ(RSMarshallingHelper::Unmarshalling(parcel, newImage), true);

    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    Drawing::Brush brush;
    Drawing::Rect rect = Drawing::Rect(0, 0, 100, 100);
    canvas.AttachBrush(brush);
    newImage->CanvasDrawImage(canvas, rect, Drawing::SamplingOptions());
    newImage->CanvasDrawImage(canvas, rect, Drawing::SamplingOptions());
    canvas.DetachBrush();

    MessageParcel parcel2;
    EXPECT_EQ(RSMarshallingHelper::Marshalling(parcel2, rsImage), true);
    std::shared_ptr<RSImage> newImage2;
    EXPECT_EQ(RSMarshallingHelper::Unmarshalling(parcel2, newImage2), true);

    RSImageCache::Instance().CachePixelMap(1, nullptr);
    RSImageCache::Instance().CachePixelMap(0, pixelMap);
    RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(1, nullptr);
    RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(0, nullptr);

    auto img = std::make_shared<Drawing::Image>();
    RSImageCache::Instance().CacheDrawingImage(0, img);

    EXPECT_EQ(RSImageCache::Instance().GetDrawingImageCache(0), nullptr);

    RSImageCache::Instance().IncreaseDrawingImageCacheRefCount(0);
}

/**
 * @tc.name: SetInnerRectTest
 * @tc.desc: Verify function SetInnerRect
 * @tc.type:FUNC
 * @tc.require: issuesI9MO9U
 */
HWTEST_F(RSImageTest, SetInnerRectTest, TestSize.Level1)
{
    auto rsImage = std::make_shared<RSImage>();
    auto innerRect = std::make_optional<Drawing::RectI>();
    rsImage->SetInnerRect(innerRect);
    EXPECT_NE(rsImage, nullptr);
}

/**
 * @tc.name: SetPaintTest
 * @tc.desc: Verify function SetPaint
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSImageTest, SetPaintTest, TestSize.Level1)
{
    auto rsImage = std::make_shared<RSImage>();
    ASSERT_NE(rsImage, nullptr);
    Drawing::Paint paint;
    rsImage->SetPaint(paint);
    EXPECT_EQ(rsImage->paint_, paint);
}

/**
 * @tc.name: dumpTest
 * @tc.desc: Verify function dump
 * @tc.type:FUNC
 * @tc.require: issuesI9MO9U
 */
HWTEST_F(RSImageTest, dumpTest, TestSize.Level1)
{
    auto rsImage = std::make_shared<RSImage>();
    auto innerRect = std::make_optional<Drawing::RectI>();
    ASSERT_NE(rsImage, nullptr);
    std::string desc = "dump ";
    rsImage->dump(desc, 0);
    EXPECT_NE(desc, "dump ");
}
} // namespace OHOS::Rosen
