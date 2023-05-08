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

#include "draw/canvas.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class CanvasTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void CanvasTest::SetUpTestCase() {}
void CanvasTest::TearDownTestCase() {}
void CanvasTest::SetUp() {}
void CanvasTest::TearDown() {}

/**
 * @tc.name: CreateAndDestroy001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CreateAndDestroy001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    EXPECT_TRUE(nullptr != canvas);
}

/**
 * @tc.name: CanvasDrawRegionTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasDrawRegionTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Region region;
    canvas->DrawRegion(region);
}

/**
 * @tc.name: CanvasDrawBitmapTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasDrawBitmapTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Bitmap bitmap;
    canvas->DrawBitmap(bitmap, 10.0f, 10.0f);
}

/**
 * @tc.name: CanvasDrawImageTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasDrawImageTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Image image;
    SamplingOptions samplingOptions;
    canvas->DrawImage(image, 10.0f, 10.0f, samplingOptions);
}

/**
 * @tc.name: CanvasDrawImageRectTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasDrawImageRectTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Image image;
    Rect srcRect(0.0f, 0.0f, 10.0f, 20.0f);
    Rect dstRect(0.0f, 0.0f, 10.0f, 20.0f);
    SamplingOptions samplingOptions;
    canvas->DrawImageRect(image, srcRect, dstRect, samplingOptions);
}

/**
 * @tc.name: CanvasDrawImageRectTest002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasDrawImageRectTest002, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Image image;
    Rect dstRect(0.0f, 0.0f, 10.0f, 20.0f);
    SamplingOptions samplingOptions;
    canvas->DrawImageRect(image, dstRect, samplingOptions);
}

/**
 * @tc.name: CanvasDrawPictureTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasDrawPictureTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Picture pic;
    canvas->DrawPicture(pic);
}

/**
 * @tc.name: CanvasClipRectTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasClipRectTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Rect rect(0.0f, 0.0f, 10.0f, 20.0f);
    canvas->ClipRect(rect, ClipOp::DIFFERENCE, true);
}

/**
 * @tc.name: CanvasClipRoundRectTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasClipRoundRectTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Rect rect(0.0f, 0.0f, 10.0f, 20.0f);
    RoundRect roundRect(rect, 1.0f, 1.0f);
    canvas->ClipRoundRect(roundRect, ClipOp::DIFFERENCE, true);
}

/**
 * @tc.name: CanvasClipPathTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasClipPathTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Path path;
    canvas->ClipPath(path, ClipOp::DIFFERENCE, true);
}

/**
 * @tc.name: CanvasSetMatrixTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasSetMatrixTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Matrix matrix;
    canvas->SetMatrix(matrix);
}

/**
 * @tc.name: CanvasResetMatrixTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasResetMatrixTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Matrix matrix;
    canvas->SetMatrix(matrix);
    canvas->ResetMatrix();
}

/**
 * @tc.name: CanvasConcatMatrixTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasConcatMatrixTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    Matrix matrix;
    canvas->ConcatMatrix(matrix);
}

/**
 * @tc.name: CanvasTranslateTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasTranslateTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Translate(1.0f, 1.0f);
}

/**
 * @tc.name: CanvasScaleTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasScaleTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Scale(1.0f, 1.0f);
}

/**
 * @tc.name: CanvasRotateTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasRotateTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Rotate(60.0f);
}

/**
 * @tc.name: CanvasRotateTest002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasRotateTest002, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Rotate(60.0f, 10.0f, 10.0f);
}

/**
 * @tc.name: CanvasShearTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasShearTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Shear(10.0f, 10.0f);
}

/**
 * @tc.name: CanvasFlushTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasFlushTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Flush();
}

/**
 * @tc.name: CanvasClearTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasClearTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Clear(Color::COLOR_BLUE);
}

/**
 * @tc.name: CanvasSaveTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(CanvasTest, CanvasSaveTest001, TestSize.Level1)
{
    auto canvas = std::make_unique<Canvas>();
    ASSERT_TRUE(nullptr != canvas);
    canvas->Save();
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
