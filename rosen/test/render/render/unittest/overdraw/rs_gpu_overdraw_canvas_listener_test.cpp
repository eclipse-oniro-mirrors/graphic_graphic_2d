/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "platform/ohos/overdraw/rs_gpu_overdraw_canvas_listener.h"
#include "platform/ohos/overdraw/rs_listened_canvas.h"

#include "third_party/skia/include/core/SkRRect.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkRegion.h"
#include "third_party/skia/include/core/SkScalar.h"
#include "third_party/skia/include/core/SkBlendMode.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
constexpr float SET_XORY1 = 1.0f;
constexpr float SET_XORY2 = 2.0f;
constexpr uint32_t SET_TOP = 100;
constexpr uint32_t SET_BOTTOM = 100;
class RSGPUOverdrawCanvasListenerUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSGPUOverdrawCanvasListenerUnitTest::SetUpTestCase() {}
void RSGPUOverdrawCanvasListenerUnitTest::TearDownTestCase() {}
void RSGPUOverdrawCanvasListenerUnitTest::SetUp() {}
void RSGPUOverdrawCanvasListenerUnitTest::TearDown() {}

/**
 * @tc.name: TestCreate001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestCreate001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    delete listener;
}

/**
 * @tc.name: TestonDrawRect001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawRect001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Rect rect;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawRect(rect);
    EXPECT_TRUE(listener);
    delete listener;
}

/**
 * @tc.name: TestonDrawOval001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawOval001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Rect rect;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawOval(rect);
    EXPECT_TRUE(listener);
    delete listener;
}

/**
 * @tc.name: TestonDrawArc001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawArc001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Rect rect;
    Drawing::scalar startAngle = 0.0;
    Drawing::scalar sweepAngle = 0.0;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawArc(rect, startAngle, sweepAngle);
    EXPECT_TRUE(listener);
    delete listener;
}

/**
 * @tc.name: TestonDrawArc002
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawArc002, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Rect rect;
    Drawing::scalar startAngle = 0.0;
    Drawing::scalar sweepAngle = 0.0;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawArc(rect, startAngle, sweepAngle);
    EXPECT_TRUE(listener);
    delete listener;
}

/**
 * @tc.name: TestonDrawPath001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawPath001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Path path;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawPath(path);
    EXPECT_TRUE(listener);
    delete listener;
}

/**
 * @tc.name: TestonDrawRegion001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawRegion001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Region region;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawRegion(region);
    EXPECT_TRUE(listener);
    delete listener;
}

/**
 * @tc.name: TestonDrawPicture001
 * @tc.desc: test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestonDrawPicture001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::Picture picture;
    auto listener = new RSGPUOverdrawCanvasListener(canvas);
    EXPECT_NE(listener, nullptr);
    listener->DrawPicture(picture);
    delete listener;
}

/**
 * @tc.name: TestDrawAndDrawPoint001
 * @tc.desc: Draw and DrawPoint Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestDrawAndDrawPoint001, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);

    // listener.listenedSurface_->GetImageSnapshot() is nullptr
    std::shared_ptr<Drawing::Surface> listenedSurface = std::make_shared<Drawing::Surface>();
    listener.listenedSurface_ = listenedSurface;
    EXPECT_TRUE(listener.IsValid());
    EXPECT_FALSE(listener.listenedSurface_->GetImageSnapshot());
    listener.Draw();
    listener.DrawPoint(Drawing::Point(SET_XORY1, SET_XORY1));
}

/**
 * @tc.name: TestOverdrawCanvaIsNull002
 * @tc.desc: OverdrawCanva is Null Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestOverdrawCanvaIsNull002, TestSize.Level1)
{
    // When listener.listener_ is nullptr, no operation will be performed on the RSGPUOverdrawCanvasListener
    // object, so writing the relevant functions together will not have any impact. If there is an operation on
    // listener.listener_ later, pay attention to modifying the test case
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);

    listener.DrawLine(Drawing::Point(SET_XORY1, SET_XORY1), Drawing::Point(SET_XORY2, SET_XORY2));

    listener.DrawRect(Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM));

    Drawing::RoundRect roundRectTest1;
    listener.DrawRoundRect(roundRectTest1);

    Drawing::RoundRect roundRectTest2;
    Drawing::RoundRect innerTest1;
    listener.DrawNestedRoundRect(roundRectTest2, innerTest1);

    listener.DrawArc(Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM), SET_XORY1, SET_XORY2);

    listener.DrawPie(Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM), SET_XORY1, SET_XORY2);

    listener.DrawOval(Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM));

    listener.DrawCircle(Drawing::Point(SET_XORY1, SET_XORY1), SET_XORY2);

    Drawing::Path path;
    listener.DrawPath(path);

    Drawing::Bitmap bitmap;
    listener.DrawBitmap(bitmap, SET_XORY1, SET_XORY1);

    Drawing::Image imageTest1;
    Drawing::SamplingOptions samplingTest1;
    listener.DrawImage(imageTest1, SET_XORY1, SET_XORY1, samplingTest1);

    Drawing::Image imageTest2;
    Drawing::SamplingOptions samplingTest2;
    listener.DrawImageRect(imageTest2, Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM),
        Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM), samplingTest2,
        Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT);

    Drawing::Image imageTest3;
    Drawing::SamplingOptions samplingTest3;
    listener.DrawImageRect(imageTest3, Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM), samplingTest3);

    Drawing::Pen pen;
    listener.AttachPen(pen);

    Drawing::Brush brush;
    listener.AttachBrush(brush);

    listener.DetachPen();
    listener.DetachBrush();

    EXPECT_FALSE(listener.overdrawCanvas_);
}

/**
 * @tc.name: TestDrawRegionWithSpecifiedRegion003
 * @tc.desc: DrawRegionWithSpecifiedRegion Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestDrawRegionWithSpecifiedRegion003, TestSize.Level1)
{
    // The calling function is empty internally
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);
    Drawing::Brush brush;
    listener.DrawBackground(brush);

    Drawing::Path path;
    Drawing::Point3 planeParams;
    Drawing::Point3 devLightPos;
    Drawing::Color ambientColor;
    Drawing::Color spotColor;
    listener.DrawShadow(path, planeParams, devLightPos, SET_XORY1, ambientColor, spotColor, Drawing::ShadowFlags::NONE);

    Drawing::Picture picture;
    listener.DrawPicture(picture);

    listener.Clear(Drawing::Color::COLOR_BLACK);
    EXPECT_TRUE(listener.overdrawCanvas_);
}

/**
 * @tc.name: TestDrawingFunctions004
 * @tc.desc: DrawingFunctions Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestDrawingFunctions004, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);
    std::shared_ptr<Drawing::Canvas> canvasTest = std::make_shared<Drawing::Canvas>();
    EXPECT_TRUE(canvasTest);
    std::shared_ptr<Drawing::OverDrawCanvas> overdrawCanvas = std::make_shared<Drawing::OverDrawCanvas>(canvasTest);
    EXPECT_TRUE(overdrawCanvas);
    listener.overdrawCanvas_ = overdrawCanvas;
    EXPECT_TRUE(listener.overdrawCanvas_);

    Drawing::RoundRect roundRectTest1;
    listener.DrawRoundRect(roundRectTest1);

    Drawing::RoundRect roundRectTest2;
    Drawing::RoundRect roundRectTest3;
    listener.DrawNestedRoundRect(roundRectTest2, roundRectTest3);

    listener.overdrawCanvas_->GetMutableBrush().style_ = Drawing::Paint::PAINT_NONE;
    listener.overdrawCanvas_->GetMutablePen().style_ = Drawing::Paint::PAINT_NONE;

    listener.DrawArc(Drawing::Rect(SET_XORY1, SET_XORY1, SET_TOP, SET_BOTTOM), SET_XORY2, SET_XORY2);

    listener.DrawPie(Drawing::Rect(SET_XORY1, SET_XORY1, SET_TOP, SET_BOTTOM), SET_XORY1, SET_XORY2);

    listener.DrawOval(Drawing::Rect(SET_XORY1, SET_XORY1, SET_TOP, SET_BOTTOM));

    listener.DrawCircle(Drawing::Point(SET_XORY1, SET_XORY1), SET_XORY2);
}

/**
 * @tc.name: TestDrawingFunctions005
 * @tc.desc: DrawingFunctions Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestDrawingFunctions005, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);
    std::shared_ptr<Drawing::Canvas> canvasTest = std::make_shared<Drawing::Canvas>();
    EXPECT_TRUE(canvasTest);
    std::shared_ptr<Drawing::OverDrawCanvas> overdrawCanvas = std::make_shared<Drawing::OverDrawCanvas>(canvasTest);
    EXPECT_TRUE(overdrawCanvas);
    listener.overdrawCanvas_ = overdrawCanvas;
    EXPECT_TRUE(listener.overdrawCanvas_);

    listener.DrawLine(Drawing::Point(SET_XORY1, SET_XORY1), Drawing::Point(SET_XORY2, SET_XORY1));

    Drawing::Rect rect = Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM);
    listener.DrawRect(rect);

    Drawing::Path path;
    listener.DrawPath(path);
}

/**
 * @tc.name: TestBitmapFunctions006
 * @tc.desc: BitmapFunctions Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestBitmapFunctions006, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);
    std::shared_ptr<Drawing::Canvas> canvasTest = std::make_shared<Drawing::Canvas>();
    EXPECT_TRUE(canvasTest);
    std::shared_ptr<Drawing::OverDrawCanvas> overdrawCanvas = std::make_shared<Drawing::OverDrawCanvas>(canvasTest);
    EXPECT_TRUE(overdrawCanvas);
    listener.overdrawCanvas_ = overdrawCanvas;
    EXPECT_TRUE(listener.overdrawCanvas_);

    Drawing::Bitmap bitmap;
    listener.DrawBitmap(bitmap, SET_XORY1, SET_XORY1);
}

/**
 * @tc.name: TestImageFunctions007
 * @tc.desc: ImageFunctionsTest Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestImageFunctions007, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);
    std::shared_ptr<Drawing::Canvas> canvasTest = std::make_shared<Drawing::Canvas>();
    EXPECT_TRUE(canvasTest);
    std::shared_ptr<Drawing::OverDrawCanvas> overdrawCanvas = std::make_shared<Drawing::OverDrawCanvas>(canvasTest);
    EXPECT_TRUE(overdrawCanvas);
    listener.overdrawCanvas_ = overdrawCanvas;
    EXPECT_TRUE(listener.overdrawCanvas_);

    Drawing::Image imageTest1;
    Drawing::SamplingOptions samplingTest1;
    listener.DrawImage(imageTest1, SET_XORY1, SET_XORY1, samplingTest1);

    Drawing::Image imageTest2;
    Drawing::SamplingOptions samplingTest2;
    listener.DrawImageRect(imageTest2, Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM),
        Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM), samplingTest2,
        Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT);

    Drawing::Image imageTest3;
    Drawing::SamplingOptions samplingTest3;
    listener.DrawImageRect(imageTest3, Drawing::Rect(0, 0, SET_TOP, SET_BOTTOM), samplingTest3);
}

/**
 * @tc.name: TestPenAndBrushFunctions008
 * @tc.desc: PenAndBrushFunctions Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSGPUOverdrawCanvasListenerUnitTest, TestPenAndBrushFunctions008, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSGPUOverdrawCanvasListener listener(canvas);
    std::shared_ptr<Drawing::Canvas> canvasTest = std::make_shared<Drawing::Canvas>();
    EXPECT_TRUE(canvasTest);
    std::shared_ptr<Drawing::OverDrawCanvas> overdrawCanvas = std::make_shared<Drawing::OverDrawCanvas>(canvasTest);
    EXPECT_TRUE(overdrawCanvas);
    listener.overdrawCanvas_ = overdrawCanvas;
    EXPECT_TRUE(listener.overdrawCanvas_);

    Drawing::Pen pen;
    listener.AttachPen(pen);

    Drawing::Brush brush;
    listener.AttachBrush(brush);

    listener.DetachPen();
    listener.DetachBrush();
}
} // namespace Rosen
} // namespace OHOS
