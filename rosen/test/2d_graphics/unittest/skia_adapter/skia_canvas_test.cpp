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

#include <cstddef>
#include "gtest/gtest.h"
#include "skia_adapter/skia_canvas.h"
#include "draw/core_canvas.h"
#include "skia_adapter/skia_canvas_autocache.h"
#include "skia_adapter/skia_oplist_handle.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class SkiaCanvasTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SkiaCanvasTest::SetUpTestCase() {}
void SkiaCanvasTest::TearDownTestCase() {}
void SkiaCanvasTest::SetUp() {}
void SkiaCanvasTest::TearDown() {}

/**
 * @tc.name: Bind001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, Bind001, TestSize.Level1)
{
    Bitmap bitmap;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.Bind(bitmap);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.Bind(bitmap);
}

/**
 * @tc.name: DrawPoint001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawPoint001, TestSize.Level1)
{
    Point point;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawPoint(point, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawPoint(point, paint);
}

/**
 * @tc.name: DrawLine001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawLine001, TestSize.Level1)
{
    Point startPt;
    Point endPt;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawLine(startPt, endPt, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawLine(startPt, endPt, paint);
}

/**
 * @tc.name: DrawRect001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawRect001, TestSize.Level1)
{
    Rect rect;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawRect(rect, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawRect(rect, paint);
}

/**
 * @tc.name: DrawRoundRect001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawRoundRect001, TestSize.Level1)
{
    RoundRect roundRect;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawRoundRect(roundRect, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawRoundRect(roundRect, paint);
}

/**
 * @tc.name: DrawNestedRoundRect001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawNestedRoundRect001, TestSize.Level1)
{
    RoundRect outer;
    RoundRect inner;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawNestedRoundRect(outer, inner, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawNestedRoundRect(outer, inner, paint);
}

/**
 * @tc.name: DrawArc001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawArc001, TestSize.Level1)
{
    Rect oval;
    scalar startAngle = 30.0f;
    scalar sweepAngle = 45.0f;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawArc(oval, startAngle, sweepAngle, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawArc(oval, startAngle, sweepAngle, paint);
}

/**
 * @tc.name: DrawPie001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawPie001, TestSize.Level1)
{
    Rect oval;
    scalar startAngle = 45.0f;
    scalar sweepAngle = 60.0f;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawPie(oval, startAngle, sweepAngle, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawPie(oval, startAngle, sweepAngle, paint);
}

/**
 * @tc.name: DrawOval001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawOval001, TestSize.Level1)
{
    Rect oval;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawOval(oval, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawOval(oval, paint);
}

/**
 * @tc.name: DrawCircle001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawCircle001, TestSize.Level1)
{
    Point centerPt;
    scalar radius = 20.0f;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawCircle(centerPt, radius, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawCircle(centerPt, radius, paint);
}

/**
 * @tc.name: DrawPath001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawPath001, TestSize.Level1)
{
    Path path;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawPath(path, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawPath(path, paint);
}

/**
 * @tc.name: DrawPathWithStencil001
 * @tc.desc: Test DrawPathWithStencil
 * @tc.type: FUNC
 * @tc.require: IBROZ2
 */
HWTEST_F(SkiaCanvasTest, DrawPathWithStencil001, TestSize.Level1)
{
    constexpr uint32_t stencilVal{10};
    Path path;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawPathWithStencil(path, stencilVal, paint);
    EXPECT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawPathWithStencil(path, stencilVal, paint);
    EXPECT_TRUE(skiaCanvas.ExportSkCanvas() == nullptr);
}

/**
 * @tc.name: DrawBackground001
 * @tc.desc: Draw Background Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, DrawBackground001, TestSize.Level2)
{
    Brush brush;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawBackground(brush);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawBackground(brush);
}

/**
 * @tc.name: DrawShadow001
 * @tc.desc: Draw Shadow Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, DrawShadow001, TestSize.Level2)
{
    Path path;
    Point3 planeParams;
    Point3 devLightPos;
    Color ambientColor;
    Color spotColor;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawShadow(path, planeParams, devLightPos, 1.0f, ambientColor, spotColor, ShadowFlags::NONE);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawShadow(path, planeParams, devLightPos, 1.0f, ambientColor, spotColor, ShadowFlags::NONE);
}

/**
 * @tc.name: DrawShadowStyle001
 * @tc.desc: Draw ShadowStyle Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, DrawShadowStyle001, TestSize.Level2)
{
    Path path;
    Point3 planeParams;
    Point3 devLightPos;
    Color ambientColor;
    Color spotColor;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawShadowStyle(path, planeParams, devLightPos, 1.0f, ambientColor, spotColor, ShadowFlags::NONE, true);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawShadowStyle(path, planeParams, devLightPos, 1.0f, ambientColor, spotColor, ShadowFlags::NONE, true);
}

/**
 * @tc.name: DrawBitmap001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawBitmap001, TestSize.Level1)
{
    Bitmap bitmap;
    scalar px = 60.0f;
    scalar py = 30.0f;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawBitmap(bitmap, px, py, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawBitmap(bitmap, px, py, paint);
}

/**
 * @tc.name: DrawImage001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawImage001, TestSize.Level1)
{
    Image image;
    scalar px = 30.0f;
    scalar py = 65.0f;
    SamplingOptions sampling;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawImage(image, px, py, sampling, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawImage(image, px, py, sampling, paint);
}

/**
 * @tc.name: DrawImageWithStencil001
 * @tc.desc: Test DrawImageWithStencil
 * @tc.type: FUNC
 * @tc.require: IBROZ2
 */
HWTEST_F(SkiaCanvasTest, DrawImageWithStencil001, TestSize.Level1)
{
    constexpr uint32_t stencilVal{10};
    Image image;
    scalar px = 30.0f;
    scalar py = 65.0f;
    SamplingOptions sampling;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawImageWithStencil(image, px, py, sampling, stencilVal, paint);
    EXPECT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawImageWithStencil(image, px, py, sampling, stencilVal, paint);
    EXPECT_TRUE(skiaCanvas.ExportSkCanvas() == nullptr);
}

/**
 * @tc.name: DrawImageRect001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawImageRect001, TestSize.Level1)
{
    Image image;
    Rect src;
    Rect dst;
    SamplingOptions sampling;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawImageRect(image, src, dst, sampling, SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawImageRect(image, src, dst, sampling, SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT, paint);
}

/**
 * @tc.name: DrawImageRect002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawImageRect002, TestSize.Level1)
{
    Image image;
    Rect dst;
    SamplingOptions sampling;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawImageRect(image, dst, sampling, paint);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawImageRect(image, dst, sampling, paint);
}

/**
 * @tc.name: DrawPicture001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, DrawPicture001, TestSize.Level1)
{
    Picture picture;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.DrawPicture(picture);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.DrawPicture(picture);
}

/**
 * @tc.name: ClipRoundRect001
 * @tc.desc: Clip Round Rect Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, ClipRoundRect001, TestSize.Level2)
{
    RoundRect roundRect;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.ClipRoundRect(roundRect, ClipOp::DIFFERENCE, false);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.ClipRoundRect(roundRect, ClipOp::DIFFERENCE, false);
}

/**
 * @tc.name: ClipPath001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, ClipPath001, TestSize.Level1)
{
    Path path;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.ClipPath(path, ClipOp::DIFFERENCE, false);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.ClipPath(path, ClipOp::DIFFERENCE, false);
}

/**
 * @tc.name: SetMatrix001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, SetMatrix001, TestSize.Level1)
{
    Matrix matrix;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.SetMatrix(matrix);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.SetMatrix(matrix);
}

/**
 * @tc.name: ResetMatrix001
 * @tc.desc: Reset Matrix Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, ResetMatrix001, TestSize.Level2)
{
    Matrix matrix;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.SetMatrix(matrix);
    skiaCanvas.ResetMatrix();

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.ResetMatrix();
}

/**
 * @tc.name: ConcatMatrix001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.author:
 */
HWTEST_F(SkiaCanvasTest, ConcatMatrix001, TestSize.Level1)
{
    Matrix matrix;
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.ConcatMatrix(matrix);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.ConcatMatrix(matrix);
}

/**
 * @tc.name: Rotate001
 * @tc.desc: Rotate Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, Rotate001, TestSize.Level2)
{
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.Rotate(0.1f, 0.2f, 0.3f);

    skiaCanvas.ImportSkCanvas(nullptr);
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() == nullptr);
    skiaCanvas.Rotate(0.1f, 0.2f, 0.3f);
}

/**
 * @tc.name: Shear001
 * @tc.desc: Shear Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, Shear001, TestSize.Level2)
{
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.Shear(0.5f, 0.5f);

    skiaCanvas.ImportSkCanvas(nullptr);
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() == nullptr);
    skiaCanvas.Shear(0.5f, 0.5f);
}

/**
 * @tc.name: Flush001
 * @tc.desc: Flush Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, Flush001, TestSize.Level2)
{
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.Flush();

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.Flush();
}

/**
 * @tc.name: SaveLayer001
 * @tc.desc: SaveLayer Test
 * @tc.type: FUNC
 * @tc.require: issuel#I6Q4ZH
 */
HWTEST_F(SkiaCanvasTest, SaveLayer001, TestSize.Level2)
{
    Rect rect;
    Brush brush;
    SaveLayerOps slo(&rect, &brush);
    SkiaCanvas skiaCanvas;
    ASSERT_TRUE(skiaCanvas.ExportSkCanvas() != nullptr);
    skiaCanvas.SaveLayer(slo);

    skiaCanvas.ImportSkCanvas(nullptr);
    skiaCanvas.SaveLayer(slo);
}

/**
 * @tc.name: GetTotalMatrixTest001
 * @tc.desc: Test for geting the total matrix of SkiaCanvas to device.
 * @tc.type: FUNC
 * @tc.require: I782P9
 */
HWTEST_F(SkiaCanvasTest, GetTotalMatrixTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);

    skiaCanvas->ImportSkCanvas(nullptr);
    auto matrix = skiaCanvas->GetTotalMatrix();
}

/**
 * @tc.name: GetLocalClipBoundsTest001
 * @tc.desc: Test for geting bounds of clip in local coordinates.
 * @tc.type: FUNC
 * @tc.require: I782P9
 */
HWTEST_F(SkiaCanvasTest, GetLocalClipBoundsTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);

    skiaCanvas->ImportSkCanvas(nullptr);
    auto rect = skiaCanvas->GetLocalClipBounds();
}

/**
 * @tc.name: GetDeviceClipBoundsTest001
 * @tc.desc: Test for geting bounds of clip in device corrdinates.
 * @tc.type: FUNC
 * @tc.require: I782P9
 */
HWTEST_F(SkiaCanvasTest, GetDeviceClipBoundsTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);

    skiaCanvas->ImportSkCanvas(nullptr);
    auto rect = skiaCanvas->GetDeviceClipBounds();
}

/**

 * @tc.name: RecordState
 * @tc.desc: Test for Canvas Record State
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SkiaCanvasTest, RecordState, TestSize.Level1)
{
    Canvas canvas;
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->RecordState(&canvas);
}

/**
 * @tc.name: BuildStateRecord
 * @tc.desc: Test for Build Record State
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SkiaCanvasTest, BuildStateRecord, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->BuildStateRecord(100.0, 100.0);
}

/**
 * @tc.name: SetParallelRender
 * @tc.desc: Test for seting parallel render.
 * @tc.type: FUNC
 * @tc.require: IC8TIV
 */
HWTEST_F(SkiaCanvasTest, SetParallelRender, TestSize.Level1)
{
    auto skiaCanvas = std::make_unique<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->SetParallelRender(true);
}

/**
 * @tc.name: GetRoundInDeviceClipBoundsTest001
 * @tc.desc: Test for geting bounds of clip in device corrdinates.
 * @tc.type: FUNC
 * @tc.require: I782P9
 */
HWTEST_F(SkiaCanvasTest, GetRoundInDeviceClipBoundsTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);

    skiaCanvas->ImportSkCanvas(nullptr);
    auto rect = skiaCanvas->GetRoundInDeviceClipBounds();
}

#ifdef RS_ENABLE_GPU
/**
 * @tc.name: GetGPUContextTest001
 * @tc.desc: Test for geting gpu context.
 * @tc.type: FUNC
 * @tc.require: I782P9
 */
HWTEST_F(SkiaCanvasTest, GetGPUContextTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);

    skiaCanvas->ImportSkCanvas(nullptr);
    auto gpuContetxt = skiaCanvas->GetGPUContext();
}
#endif

/**
 * @tc.name: GetWidth001
 * @tc.desc: Test GetWidth
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, GetWidth001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    ASSERT_TRUE(skiaCanvas->GetWidth() >= 0);
}

/**
 * @tc.name: GetHeight001
 * @tc.desc: Test GetHeight
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, GetHeight001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    ASSERT_TRUE(skiaCanvas->GetHeight() >= 0);
}

/**
 * @tc.name: GetImageInfo001
 * @tc.desc: Test GetImageInfo
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, GetImageInfo001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    ASSERT_TRUE(skiaCanvas->GetImageInfo().GetWidth() >= 0);
}

/**
 * @tc.name: ReadPixels001
 * @tc.desc: Test ReadPixels
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, ReadPixels001, TestSize.Level1)
{
    auto skiaCanvas1 = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas1 != nullptr);
    ImageInfo imageInfo;
    ASSERT_TRUE(!skiaCanvas1->ReadPixels(imageInfo, nullptr, 0, 0, 0));
    Bitmap bitmap;
    ASSERT_TRUE(!skiaCanvas1->ReadPixels(bitmap, 0, 0));

    auto skiaCanvas2 = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas2 != nullptr);
    ASSERT_TRUE(!skiaCanvas2->ReadPixels(imageInfo, nullptr, 0, 0, 0));
    ASSERT_TRUE(!skiaCanvas2->ReadPixels(bitmap, 0, 0));
}

/**
 * @tc.name: DrawPoints001
 * @tc.desc: Test DrawPoints
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawPoints001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    skiaCanvas->DrawPoints(PointMode::POINTS_POINTMODE, 0, {}, paint);
}

/**
 * @tc.name: DrawColor001
 * @tc.desc: Test DrawColor
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawColor001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->DrawColor(0xFF000000, BlendMode::COLOR_BURN);
}

/**
 * @tc.name: ClearStencil001
 * @tc.desc: Test ClearStencil
 * @tc.type: FUNC
 * @tc.require: IBROZ2
 */
HWTEST_F(SkiaCanvasTest, ClearStencil001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    RectI rect;
    constexpr uint32_t stencilVal{10};
    skiaCanvas->ClearStencil(rect, stencilVal);
    EXPECT_TRUE(skiaCanvas->ExportSkCanvas() != nullptr);

    skiaCanvas->ImportSkCanvas(nullptr);
    skiaCanvas->ClearStencil(rect, stencilVal);
    EXPECT_TRUE(skiaCanvas->ExportSkCanvas() == nullptr);
}

/**
 * @tc.name: ClipRect001
 * @tc.desc: Test ClipRect
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, ClipRect001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    Rect rect;
    skiaCanvas->ClipRect(rect, ClipOp::DIFFERENCE, true);
}

/**
 * @tc.name: ClipIRect001
 * @tc.desc: Test ClipIRect
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, ClipIRect001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    RectI rect;
    skiaCanvas->ClipIRect(rect, ClipOp::DIFFERENCE);
}

/**
 * @tc.name: ClipRegion001
 * @tc.desc: Test ClipRegion
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, ClipRegion001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    Region region;
    skiaCanvas->ClipRegion(region, ClipOp::DIFFERENCE);
}

/**
 * @tc.name: IsClipEmpty001
 * @tc.desc: Test IsClipEmpty
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, IsClipEmpty001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    ASSERT_TRUE(skiaCanvas->IsClipEmpty());
    auto skiaCanvas2 = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas2 != nullptr);
    ASSERT_TRUE(!skiaCanvas2->IsClipEmpty());
}

/**
 * @tc.name: IsClipRect001
 * @tc.desc: Test IsClipRect
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, IsClipRect001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    ASSERT_TRUE(!skiaCanvas->IsClipRect());
    auto skiaCanvas2 = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas2 != nullptr);
    ASSERT_TRUE(!skiaCanvas2->IsClipRect());
}

/**
 * @tc.name: QuickReject001
 * @tc.desc: Test QuickReject
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, QuickReject001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    Rect rect{0, 0, 1, 1};
    ASSERT_TRUE(skiaCanvas->QuickReject(rect));
    auto skiaCanvas2 = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas2 != nullptr);
    ASSERT_TRUE(!skiaCanvas2->QuickReject(rect));
}

/**
 * @tc.name: Translate001
 * @tc.desc: Test Translate
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, Translate001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->Translate(1, 1);
}

/**
 * @tc.name: Scale001
 * @tc.desc: Test Scale
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, Scale001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->Scale(1, 1);
}

/**
 * @tc.name: Clear001
 * @tc.desc: Test Clear
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, Clear001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->Clear(0xFF000000); // 0xFF000000: color
}

/**
 * @tc.name: Save001
 * @tc.desc: Test Save
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, Save001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>(nullptr);
    ASSERT_TRUE(skiaCanvas != nullptr);
    skiaCanvas->Save();
    skiaCanvas->Restore();
    ASSERT_TRUE(skiaCanvas->GetSaveCount() == 0);
}

/**
 * @tc.name: DrawSymbol001
 * @tc.desc: Test DrawSymbol
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawSymbol001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    DrawingHMSymbolData drawingHMSymbolData;
    Path path;
    drawingHMSymbolData.path_ = path;
    DrawingRenderGroup group;
    DrawingGroupInfo info{{1, 1}, {1, 1}};
    group.groupInfos = {info};
    drawingHMSymbolData.symbolInfo_.renderGroups = {group};
    Point locate;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    skiaCanvas->DrawSymbol(drawingHMSymbolData, locate, paint);
    skiaCanvas->ImportSkCanvas(nullptr);
    skiaCanvas->DrawSymbol(drawingHMSymbolData, locate, paint);
}

/**
 * @tc.name: DrawTextBlob001
 * @tc.desc: Test DrawTextBlob
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawTextBlob001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    skiaCanvas->DrawTextBlob(nullptr, 0, 0, paint);
    Font font;
    auto textBlob = TextBlob::MakeFromString("11", font, TextEncoding::UTF8);
    skiaCanvas->DrawTextBlob(textBlob.get(), 0, 0, paint);
    skiaCanvas->ImportSkCanvas(nullptr);
    skiaCanvas->DrawTextBlob(nullptr, 0, 0, paint);
}

/**
 * @tc.name: DrawPatch001
 * @tc.desc: Test DrawPatch
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawPatch001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    float width = 100.0;
    float height = 100.0;
    float segmentWidthOne = width / 3.0;
    float segmentWidthTwo = width / 3.0 * 2.0;
    float segmentHeightOne = height / 3.0;
    float segmentHeightTwo = height / 3.0 * 2.0;
    Point ctrlPoints[12] = {
        // top edge control points
        {0.0f, 0.0f}, {segmentWidthOne, 0.0f}, {segmentWidthTwo, 0.0f}, {width, 0.0f},
        // right edge control points
        {width, segmentHeightOne}, {width, segmentHeightTwo},
        // bottom edge control points
        {width, height}, {segmentWidthTwo, height}, {segmentWidthOne, height}, {0.0f, height},
        // left edge control points
        {0.0f, segmentHeightTwo}, {0.0f, segmentHeightOne}
    };
    ColorQuad colors[4] = {0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000};
    Point texCoords[4] = {
        {0.0f, 0.0f}, {width, 0.0f}, {width, height}, {0.0f, height}
    };
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    skiaCanvas->DrawPatch(ctrlPoints, colors, texCoords, BlendMode::COLOR_BURN, paint);
    skiaCanvas->DrawPatch(nullptr, nullptr, nullptr, BlendMode::COLOR_BURN, paint);
    skiaCanvas->ImportSkCanvas(nullptr);
    skiaCanvas->DrawPatch(nullptr, nullptr, nullptr, BlendMode::COLOR_BURN, paint);
}

/**
 * @tc.name: DrawVertices001
 * @tc.desc: Test DrawVertices
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawVertices001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    Vertices vertices;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    skiaCanvas->DrawVertices(vertices, BlendMode::COLOR_BURN, paint);
    skiaCanvas->ImportSkCanvas(nullptr);
    skiaCanvas->DrawVertices(vertices, BlendMode::COLOR_BURN, paint);
}

/**
 * @tc.name: DrawImageNine001
 * @tc.desc: Test DrawImageNine
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawImageNine001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    Image image;
    RectI center;
    Rect dst;
    Brush brush;
    skiaCanvas->DrawImageNine(&image, center, dst, FilterMode::LINEAR, &brush);
    skiaCanvas->DrawImageNine(&image, center, dst, FilterMode::LINEAR, nullptr);
}

/**
 * @tc.name: DrawImageLattice001
 * @tc.desc: Test DrawImageLattice
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawImageLattice001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    Image image;
    Lattice lattice;
    Rect dst;
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL);
    skiaCanvas->DrawImageLattice(&image, lattice, dst, FilterMode::LINEAR, paint);
}

/**
 * @tc.name: DrawImageEffectHPSTest001
 * @tc.desc: Test DrawImageEffectHPSTest
 * @tc.type: FUNC
 * @tc.require: I91EH1
 */
HWTEST_F(SkiaCanvasTest, DrawImageEffectHPSTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkiaCanvas>();
    ASSERT_TRUE(skiaCanvas != nullptr);
    Image image;
    Rect dst;
    Rect src;
    std::vector<std::shared_ptr<HpsEffectParameter>> hpsEffectParams;
    hpsEffectParams.push_back(std::make_shared<HpsBlurEffectParameter>(src, dst, 10.f, 1.f, 1.f));
    skiaCanvas->DrawImageEffectHPS(image, hpsEffectParams);
}

/**
 * @tc.name: OpCalculateBeforeTest001
 * @tc.desc: Test OpCalculateBefore
 * @tc.type: FUNC
 * @tc.require: I9B0X4
 */
HWTEST_F(SkiaCanvasTest, OpCalculateBeforeTest001, TestSize.Level1)
{
    SkiaCanvas skiaCanvas;
    Matrix matrix;
    ASSERT_EQ(skiaCanvas.OpCalculateBefore(matrix), true);
}

/**
 * @tc.name: OpCalculateAfterTest001
 * @tc.desc: Test OpCalculateAfter
 * @tc.type: FUNC
 * @tc.require: I9B0X4
 */
HWTEST_F(SkiaCanvasTest, OpCalculateAfterTest001, TestSize.Level1)
{
    SkiaCanvas skiaCanvas;
    Rect rect;
    auto handle = skiaCanvas.OpCalculateAfter(rect);
    ASSERT_EQ(handle, nullptr);
}

/**
 * @tc.name: OpCalculateAfterTest002
 * @tc.desc: Test OpCalculateAfter
 * @tc.type: FUNC
 * @tc.require: I9B0X4
 */
HWTEST_F(SkiaCanvasTest, OpCalculateAfterTest002, TestSize.Level1)
{
    SkiaCanvas skiaCanvas;
    Matrix matrix;
    skiaCanvas.OpCalculateBefore(matrix);
    Rect rect;
    auto handle = skiaCanvas.OpCalculateAfter(rect);
    ASSERT_EQ(handle, nullptr);
}

/**
 * @tc.name: GetOpsNumTest001
 * @tc.desc: Test GetOpsNum
 * @tc.type: FUNC
 * @tc.require: I9B0X4
 */
HWTEST_F(SkiaCanvasTest, GetOpsNumTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkCanvas>();
    ASSERT_NE(skiaCanvas, nullptr);
    Matrix matrix;
    auto m = matrix.GetImpl<SkiaMatrix>();
    ASSERT_NE(m, nullptr);
    auto tmp = std::make_shared<SkiaCanvasAutoCache>(skiaCanvas.get());
    ASSERT_NE(tmp, nullptr);
    tmp->Init(m->ExportSkiaMatrix());
    ASSERT_EQ(tmp->GetOpsNum(), 0);
}

/**
 * @tc.name: GetOpsPercentTest001
 * @tc.desc: Test GetOpsPercent
 * @tc.type: FUNC
 * @tc.require: I9B0X4
 */
HWTEST_F(SkiaCanvasTest, GetOpsPercentTest001, TestSize.Level1)
{
    auto skiaCanvas = std::make_shared<SkCanvas>();
    ASSERT_NE(skiaCanvas, nullptr);
    Matrix matrix;
    auto m = matrix.GetImpl<SkiaMatrix>();
    ASSERT_NE(m, nullptr);
    auto tmp = std::make_shared<SkiaCanvasAutoCache>(skiaCanvas.get());
    ASSERT_NE(tmp, nullptr);
    tmp->Init(m->ExportSkiaMatrix());
    ASSERT_EQ(tmp->GetOpsPercent(), 0);
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS