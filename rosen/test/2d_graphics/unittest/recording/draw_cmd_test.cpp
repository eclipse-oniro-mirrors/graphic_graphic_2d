/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "draw/surface.h"
#include "pixel_map.h"
#include "recording/cmd_list.h"
#include "recording/cmd_list_helper.h"
#include "recording/draw_cmd.h"
#include "recording/draw_cmd_list.h"
#include "recording/mask_cmd_list.h"
#include "recording/recording_canvas.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DrawCmdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DrawCmdTest::SetUpTestCase() {}
void DrawCmdTest::TearDownTestCase() {}
void DrawCmdTest::SetUp() {}
void DrawCmdTest::TearDown() {}

class DrawCmdTestCanvas : public Canvas {
public:
    ~DrawCmdTestCanvas() override = default;
    DrawingType GetDrawingType() const override
    {
        return DrawingType::COMMON;
    }

    Drawing::Surface* GetSurface() const override
    {
        return surface_;
    }

    void SetSurface(Drawing::Surface* surface)
    {
        surface_ = surface;
    }

private:
    Drawing::Surface* surface_ = nullptr;
};

/**
 * @tc.name: DrawCmdList001
 * @tc.desc: Test the creation of CmdList.
 * @tc.type: FUNC
 * @tc.require: I7SO7X
 */
HWTEST_F(DrawCmdTest, DrawCmdList001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    drawCmdList->SetWidth(10);
    drawCmdList->SetHeight(20);
    drawCmdList->AddOp<ClearOpItem::ConstructorHandle>(Color::COLOR_BLACK);
    auto cmdData = drawCmdList->GetData();

    auto newDrawCmdList = DrawCmdList::CreateFromData(cmdData, true);
    EXPECT_TRUE(newDrawCmdList != nullptr);
    newDrawCmdList->SetWidth(drawCmdList->GetWidth());
    newDrawCmdList->SetHeight(drawCmdList->GetHeight());
    EXPECT_EQ(newDrawCmdList->GetWidth(), drawCmdList->GetWidth());
    EXPECT_EQ(newDrawCmdList->GetHeight(), drawCmdList->GetHeight());

    CmdListData cmdListData = { nullptr, 0 };
    newDrawCmdList = DrawCmdList::CreateFromData(cmdListData, false);
    EXPECT_TRUE(newDrawCmdList != nullptr);
    EXPECT_EQ(newDrawCmdList->GetWidth(), 0.f);
    EXPECT_EQ(newDrawCmdList->GetHeight(), 0.f);

    auto imageData = drawCmdList->GetAllImageData();
    auto cmdList = DrawCmdList::CreateFromData(cmdData, false);
    cmdList->SetUpImageData(imageData.first, imageData.second);
}

/**
 * @tc.name: Marshalling000
 * @tc.desc: Test Marshalling
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling000, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    PaintHandle paintHandle;
    DrawPointsOpItem::ConstructorHandle handle{PointMode::POINTS_POINTMODE, {0, 0}, paintHandle};
    DrawPointsOpItem opItem{*drawCmdList, &handle};
    opItem.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas.get(), nullptr);
}

/**
 * @tc.name: BrushHandleToBrush001
 * @tc.desc: Test BrushHandleToBrush
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, BrushHandleToBrush001, TestSize.Level1)
{
    BrushHandle brushHandle;
    brushHandle.colorFilterHandle.size = 1;
    brushHandle.colorSpaceHandle.size = 1;
    brushHandle.shaderEffectHandle.size = 1;
    brushHandle.imageFilterHandle.size = 1;
    brushHandle.maskFilterHandle.size = 1;
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Brush brush;
    DrawOpItem::BrushHandleToBrush(brushHandle, *drawCmdList, brush);
}

/**
 * @tc.name: GeneratePaintFromHandle001
 * @tc.desc: Test GeneratePaintFromHandle
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, GeneratePaintFromHandle001, TestSize.Level1)
{
    PaintHandle paintHandle;
    paintHandle.colorSpaceHandle.size = 1;
    paintHandle.imageFilterHandle.size = 1;
    paintHandle.pathEffectHandle.size = 1;
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Paint paint;
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL_STROKE);
    DrawOpItem::GeneratePaintFromHandle(paintHandle, *drawCmdList, paint);
}

/**
 * @tc.name: GenerateHandleFromPaint001
 * @tc.desc: Test GenerateHandleFromPaint
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, GenerateHandleFromPaint001, TestSize.Level1)
{
    PaintHandle paintHandle;
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Paint paint;
    Filter filter;
    paint.SetFilter(filter);
    auto space = std::make_shared<ColorSpace>();
    Color4f color;
    paint.SetColor(color, space);
    auto pathEffect = PathEffect::CreateCornerPathEffect(10);
    paint.SetPathEffect(pathEffect);
    paint.SetShaderEffect(ShaderEffect::CreateColorShader(0xFF000000));
    paint.SetStyle(Paint::PaintStyle::PAINT_FILL_STROKE);
    DrawOpItem::GenerateHandleFromPaint(*drawCmdList, paint, paintHandle);
}

/**
 * @tc.name: DrawCmdTestBlurDrawLooper001
 * @tc.desc: Test BlurDrawLooper
 * @tc.type: FUNC
 * @tc.require: AR20240104201189
 */
HWTEST_F(DrawCmdTest, DrawCmdTestBlurDrawLooper001, TestSize.Level1)
{
    // recordingcanvas  width 100, height 100
    int32_t width = 100;
    int32_t height = 100;
    auto recordingCanvas = std::make_shared<RecordingCanvas>(width, height, true);
    EXPECT_TRUE(recordingCanvas != nullptr);
    auto drawCmdList = recordingCanvas->GetDrawCmdList();
    EXPECT_TRUE(drawCmdList != nullptr);
    Paint paint1;
    paint1.SetAntiAlias(true);
    // 1.f 2.f  3.f and 0x12345678 is setted to compare.
    float radius = 1.f;
    Point point{2.f, 3.f};
    Color color = Color(0x12345678);
    std::shared_ptr<BlurDrawLooper> blurDrawLooper1 = BlurDrawLooper::CreateBlurDrawLooper(radius,
        point.GetX(), point.GetY(), color);
    EXPECT_NE(blurDrawLooper1, nullptr);
    paint1.SetLooper(blurDrawLooper1);

    PaintHandle paintHandle { 0 };
    DrawOpItem::GenerateHandleFromPaint(*drawCmdList, paint1, paintHandle);
    EXPECT_TRUE(paintHandle.isAntiAlias);
    EXPECT_NE(paintHandle.blurDrawLooperHandle.size, 0);

    Paint paint2;
    DrawOpItem::GeneratePaintFromHandle(paintHandle, *drawCmdList, paint2);
    EXPECT_TRUE(paint2.IsAntiAlias());
    EXPECT_NE(paint2.GetLooper(), nullptr);
    EXPECT_TRUE(*(paint2.GetLooper()) == *blurDrawLooper1);
}

/**
 * @tc.name: DrawCmdTestBlurDrawLooper002
 * @tc.desc: Test null BlurDrawLooper
 * @tc.type: FUNC
 * @tc.require: AR20240104201189
 */
HWTEST_F(DrawCmdTest, DrawCmdTestBlurDrawLooper002, TestSize.Level1)
{
    // recordingcanvas  width 100, height 100
    int32_t width = 100;
    int32_t height = 100;
    auto recordingCanvas = std::make_shared<RecordingCanvas>(width, height, true);
    EXPECT_TRUE(recordingCanvas != nullptr);
    auto drawCmdList = recordingCanvas->GetDrawCmdList();
    EXPECT_TRUE(drawCmdList != nullptr);

    Paint paint1;
    paint1.SetAntiAlias(true);
    paint1.SetLooper(nullptr);

    PaintHandle paintHandle { 0 };
    DrawOpItem::GenerateHandleFromPaint(*drawCmdList, paint1, paintHandle);
    EXPECT_TRUE(paintHandle.isAntiAlias);
    EXPECT_EQ(paintHandle.blurDrawLooperHandle.offset, 0);
    EXPECT_EQ(paintHandle.blurDrawLooperHandle.size, 0);

    Paint paint2;
    DrawOpItem::GeneratePaintFromHandle(paintHandle, *drawCmdList, paint2);
    EXPECT_TRUE(paint2.IsAntiAlias());
    EXPECT_EQ(paint2.GetLooper(), nullptr);
}

/**
 * @tc.name: GenerateCachedOpItem001
 * @tc.desc: Test GenerateCachedOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, GenerateCachedOpItem001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    GenerateCachedOpItemPlayer player{*drawCmdList, nullptr, nullptr};
    EXPECT_FALSE(player.GenerateCachedOpItem(DrawOpItem::TEXT_BLOB_OPITEM, nullptr, 0));
    OpDataHandle opDataHandle;
    uint64_t globalUniqueId = 0;
    PaintHandle paintHandle;
    DrawTextBlobOpItem::ConstructorHandle handle{opDataHandle,
        globalUniqueId, 0, 0, paintHandle};
    EXPECT_FALSE(player.GenerateCachedOpItem(DrawOpItem::TEXT_BLOB_OPITEM, &handle, 0));
    EXPECT_FALSE(player.GenerateCachedOpItem(DrawOpItem::PICTURE_OPITEM, &handle, 0));
}

/**
 * @tc.name: PatchTypefaceIds
 * @tc.desc: Test the PatchTypefaceIds function.
 * @tc.type: FUNC
 * @tc.require: IAIBB4
 */
HWTEST_F(DrawCmdTest, PatchTypefaceIds001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    OpDataHandle opDataHandle;
    uint64_t globalUniqueId = 1;
    PaintHandle paintHandle;
    DrawTextBlobOpItem::ConstructorHandle handle{opDataHandle, globalUniqueId, 0, 0, paintHandle};
    GenerateCachedOpItemPlayer player{*drawCmdList, nullptr, nullptr};
    player.GenerateCachedOpItem(DrawOpItem::TEXT_BLOB_OPITEM, &handle, 0);
    drawCmdList->PatchTypefaceIds();
}

/**
 * @tc.name: DrawShadowOpItem001
 * @tc.desc: Test DrawShadowOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, DrawShadowOpItem001, TestSize.Level1)
{
    Path path;
    Point3 planeParams;
    Point3 devLightPos;
    Color ambientColor = 0xFF000000;
    Color spotColor = 0xFF000000;
    DrawShadowOpItem opItem{path, planeParams, devLightPos,
        10, ambientColor, spotColor, ShadowFlags::NONE}; // 10: lightRadius
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: DrawShadowStyleOpItem001
 * @tc.desc: Test DrawShadowStyleOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, DrawShadowStyleOpItem001, TestSize.Level1)
{
    Path path;
    Point3 planeParams;
    Point3 devLightPos;
    Color ambientColor = 0xFF000000;
    Color spotColor = 0xFF000000;
    DrawShadowStyleOpItem opItem{path, planeParams, devLightPos,
        10, ambientColor, spotColor, ShadowFlags::NONE, true}; // 10: lightRadius
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: ClipPathOpItem001
 * @tc.desc: Test ClipPathOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, ClipPathOpItem001, TestSize.Level1)
{
    Path path;
    ClipPathOpItem opItem{path, ClipOp::DIFFERENCE, true};
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: SaveLayerOpItem001
 * @tc.desc: Test SaveLayerOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, SaveLayerOpItem001, TestSize.Level1)
{
    SaveLayerOps ops;
    SaveLayerOpItem opItem{ops};
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    Rect rect1;
    opItem.Playback(recordingCanvas.get(), &rect1);
    Rect rect2{0, 0, 100, 100}; // 100: right, bottom
    opItem.Playback(recordingCanvas.get(), &rect2);

    Rect bounds;
    Brush brush;
    SaveLayerOps ops2{&bounds, &brush, 0};
    SaveLayerOpItem opItem2{ops2};
    opItem2.Marshalling(*drawCmdList);
    opItem2.Playback(recordingCanvas.get(), &rect1);
}

/**
 * @tc.name: DrawSymbolOpItem001
 * @tc.desc: Test DrawSymbolOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, DrawSymbolOpItem001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    DrawingHMSymbolData drawingHMSymbolData;
    DrawingSymbolLayers symbolInfo;
    DrawingRenderGroup groups;
    DrawingGroupInfo info;
    info.layerIndexes = {1, 4};
    info.maskIndexes = {1, 4};
    groups.groupInfos = {info};
    symbolInfo.renderGroups = {groups};
    symbolInfo.layers = {{1}, {1}, {1}};
    drawingHMSymbolData.symbolInfo_ = symbolInfo;
    Point point;
    Paint paint;
    DrawSymbolOpItem opItem{drawingHMSymbolData, point, paint};
    Path path;
    opItem.Marshalling(*drawCmdList);
    SymbolOpHandle symbolOpHandle;
    PaintHandle paintHandle;
    Point locate;
    DrawSymbolOpItem::ConstructorHandle handle{symbolOpHandle, locate, paintHandle};
    opItem.Unmarshalling(*drawCmdList, &handle);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas.get(), nullptr);
    opItem.Playback(nullptr, nullptr);

    DrawingHMSymbolData drawingHMSymbolData2;
    DrawSymbolOpItem opItem2{drawingHMSymbolData2, point, paint};
    opItem2.Playback(recordingCanvas.get(), nullptr);
    std::string outString;
    opItem2.DumpItems(outString);
    ASSERT_TRUE(!outString.empty());
}

/**
 * @tc.name: Marshalling001
 * @tc.desc: Test Marshalling for DrawPointOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Point point;
    PaintHandle paintHandle;
    DrawPointOpItem::ConstructorHandle handle{point, paintHandle};
    DrawPointOpItem opItem{*drawCmdList, &handle};
    opItem.Marshalling(*drawCmdList);
    auto descStr = opItem.GetOpDesc();
    opItem.DumpItems(descStr);
    ASSERT_TRUE(!descStr.empty());
}

/**
 * @tc.name: Marshalling002
 * @tc.desc: Test Marshalling for DrawPieOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling002, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Rect rect;
    PaintHandle paintHandle;
    DrawPieOpItem::ConstructorHandle handle{rect, 0, 0, paintHandle};
    DrawPieOpItem opItem{*drawCmdList, &handle};
    opItem.Marshalling(*drawCmdList);
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
}

/**
 * @tc.name: Marshalling003
 * @tc.desc: Test Marshalling for DrawOvalOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling003, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Rect rect;
    PaintHandle paintHandle;
    DrawOvalOpItem::ConstructorHandle handle{rect, paintHandle};
    DrawOvalOpItem opItem{*drawCmdList, &handle};
    opItem.Marshalling(*drawCmdList);
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
}

/**
 * @tc.name: Marshalling004
 * @tc.desc: Test Marshalling for DrawCircleOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling004, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Point point;
    PaintHandle paintHandle;
    DrawCircleOpItem::ConstructorHandle handle{point, 100, paintHandle}; // 100: radius
    DrawCircleOpItem opItem{*drawCmdList, &handle};
    opItem.Marshalling(*drawCmdList);
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
}

/**
 * @tc.name: Marshalling005
 * @tc.desc: Test Marshalling for DrawPathOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling005, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Path path;
    Paint paint;
    DrawPathOpItem opItem{path, paint};
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: Marshalling006
 * @tc.desc: Test Marshalling for DrawBackgroundOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling006, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    BrushHandle brushHandle;
    DrawBackgroundOpItem::ConstructorHandle handle{brushHandle};
    DrawBackgroundOpItem opItem{*drawCmdList, &handle};
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: Marshalling007
 * @tc.desc: Test Marshalling for DrawRegionOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling007, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Region region;
    Paint paint;
    DrawRegionOpItem opItem{region, paint};
    opItem.Marshalling(*drawCmdList);
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
}

/**
 * @tc.name: Marshalling008
 * @tc.desc: Test Marshalling for DrawVerticesOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling008, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Vertices vertices;
    Paint paint;
    DrawVerticesOpItem opItem{vertices, BlendMode::SRC_OVER, paint};
    opItem.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas.get(), nullptr);

    PaintHandle paintHandle;
    OpDataHandle verticesHandle;
    DrawVerticesOpItem::ConstructorHandle handle { verticesHandle, BlendMode::SRC_OVER, paintHandle };
    DrawVerticesOpItem opItem1 { *drawCmdList, &handle };
    opItem1.vertices_ = std::make_shared<Vertices>();
    opItem1.Marshalling(*drawCmdList);
    std::string outStr;
    opItem1.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
    opItem1.Unmarshalling(*drawCmdList, &handle);
    EXPECT_EQ(drawCmdList->opCnt_, 2);
}

/**
 * @tc.name: Marshalling009
 * @tc.desc: Test Marshalling for DrawColorOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling009, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    ColorQuad colorQuad{0};
    DrawColorOpItem::ConstructorHandle handle{colorQuad, BlendMode::SRC_OVER};
    DrawColorOpItem opItem{&handle};
    opItem.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas.get(), nullptr);
}

/**
 * @tc.name: Marshalling010
 * @tc.desc: Test Marshalling for DrawImageNineOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling010, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    OpDataHandle opDataHandle;
    RectI recti;
    Rect rect;
    BrushHandle brushHandle;
    DrawImageNineOpItem::ConstructorHandle handle{opDataHandle, recti, rect, FilterMode::NEAREST, brushHandle, true};
    Image image;
    Brush brush;
    DrawImageNineOpItem opItem{&image, recti, rect, FilterMode::NEAREST, &brush};
    opItem.Marshalling(*drawCmdList);
    opItem.Unmarshalling(*drawCmdList, &handle);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas.get(), nullptr);
    DrawImageNineOpItem opItem2{&image, recti, rect, FilterMode::NEAREST, nullptr};
    opItem2.Marshalling(*drawCmdList);
}

/**
 * @tc.name: Marshalling011
 * @tc.desc: Test Marshalling for DrawImageLatticeOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling011, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Image image;
    Lattice lattice;
    Rect dst;
    Paint paint;
    DrawImageLatticeOpItem opItem{&image, lattice, dst, FilterMode::NEAREST, paint};
    opItem.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas.get(), nullptr);

    auto holdDrawingImagefunc = [](std::shared_ptr<Drawing::Image> image) {};
    DrawImageLatticeOpItem::SetBaseCallback(holdDrawingImagefunc);
    OpDataHandle imageHandle;
    LatticeHandle latticeHandle;
    PaintHandle paintHandle;
    DrawImageLatticeOpItem::ConstructorHandle handle { imageHandle, latticeHandle, dst, FilterMode::NEAREST,
        paintHandle };
    ASSERT_TRUE(drawCmdList != nullptr);
    DrawImageLatticeOpItem opItem1 { *drawCmdList, &handle };
    DrawImageLatticeOpItem::SetBaseCallback(nullptr);
}

/**
 * @tc.name: Marshalling012
 * @tc.desc: Test Marshalling for DrawBitmapOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling012, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Bitmap bitmap;
    Paint paint;
    DrawBitmapOpItem opItem{bitmap, 0, 0, paint};
    opItem.Marshalling(*drawCmdList);

    ImageHandle bitmapHandle;
    scalar px = SCALAR_ONE;
    scalar py = BLUR_SIGMA_SCALE;
    PaintHandle paintHandle;
    DrawBitmapOpItem::ConstructorHandle handle { bitmapHandle, px, py, paintHandle };
    DrawBitmapOpItem opItem1 { *drawCmdList, &handle };

    Canvas canvas;
    Rect rect;
    opItem1.bitmap_ = std::make_shared<Bitmap>();
    opItem1.Playback(&canvas, &rect);
    opItem1.bitmap_ = nullptr;
    opItem1.Playback(&canvas, &rect);

    std::string outStr;
    opItem1.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());

    opItem1.Unmarshalling(*drawCmdList, &handle);
}

/**
 * @tc.name: Marshalling013
 * @tc.desc: Test Marshalling for DrawImageOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling013, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Image image;
    SamplingOptions options;
    Paint paint;
    DrawImageOpItem opItem{image, 0, 0, options, paint};
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: Marshalling014
 * @tc.desc: Test Marshalling for DrawImageRectOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling014, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Image image;
    Rect src;
    Rect dst;
    SamplingOptions samplingOptions;
    Paint paint;
    DrawImageRectOpItem opItem{image, src, dst, samplingOptions,
        SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT, paint, false};
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
    opItem.Marshalling(*drawCmdList);
    DrawImageRectOpItem opItem2{image, src, dst, samplingOptions,
        SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT, paint, true};
    opItem2.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    Rect rect;
    opItem2.Playback(recordingCanvas.get(), &rect);
}

/**
 * @tc.name: Marshalling015
 * @tc.desc: Test Marshalling for DrawPictureOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Marshalling015, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Picture picture;
    DrawPictureOpItem opItem{picture};
    opItem.Marshalling(*drawCmdList);
}

/**
 * @tc.name: Marshalling016
 * @tc.desc: Test Marshalling for DrawLineOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, Marshalling016, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    Point startPt;
    Point endPt;
    PaintHandle paintHandle;

    DrawLineOpItem::ConstructorHandle handle { startPt, endPt, paintHandle };
    ASSERT_TRUE(drawCmdList != nullptr);
    DrawLineOpItem opItem { *drawCmdList, &handle };
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: Marshalling017
 * @tc.desc: Test Marshalling for DrawRectOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, Marshalling017, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    Rect rect;
    PaintHandle paintHandle;
    DrawRectOpItem::ConstructorHandle handle { rect, paintHandle };
    ASSERT_TRUE(drawCmdList != nullptr);
    DrawRectOpItem opItem { *drawCmdList, &handle };
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: Marshalling018
 * @tc.desc: Test Marshalling for DrawRoundRectOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, Marshalling018, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    Point point;
    RoundRect rrect;
    PaintHandle paintHandle;
    DrawRoundRectOpItem::ConstructorHandle handle { rrect, paintHandle };
    ASSERT_TRUE(drawCmdList != nullptr);
    DrawRoundRectOpItem opItem { *drawCmdList, &handle };
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: Marshalling019
 * @tc.desc: Test Marshalling for DrawRoundRectOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, Marshalling019, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    RoundRect outerRRect;
    RoundRect innerRRect;
    PaintHandle paintHandle;
    DrawNestedRoundRectOpItem::ConstructorHandle handle { outerRRect, innerRRect, paintHandle };
    DrawNestedRoundRectOpItem opItem { *drawCmdList, &handle };
    opItem.Marshalling(*drawCmdList);
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
}

/**
 * @tc.name: Marshalling020
 * @tc.desc: Test Marshalling for DrawArcOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, Marshalling020, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    Rect rect;
    scalar startAngle = SCALAR_ONE;
    scalar sweepAngle = BLUR_SIGMA_SCALE;
    PaintHandle paintHandle;
    DrawArcOpItem::ConstructorHandle handle { rect, startAngle, sweepAngle, paintHandle };
    DrawArcOpItem opItem { *drawCmdList, &handle };
    opItem.Marshalling(*drawCmdList);
    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());
}

/**
 * @tc.name: Marshalling021
 * @tc.desc: Test Marshalling for DrawAtlasOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, Marshalling021, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    auto holdDrawingImagefunc = [](std::shared_ptr<Drawing::Image> image) {};
    DrawAtlasOpItem::SetBaseCallback(holdDrawingImagefunc);
    OpDataHandle atlas;
    std::pair<uint32_t, size_t> xform;
    std::pair<uint32_t, size_t> tex;
    std::pair<uint32_t, size_t> colors;
    SamplingOptions samplingOptions;
    bool hasCullRect = false;
    Rect cullRect;
    PaintHandle paintHandle;
    DrawAtlasOpItem::ConstructorHandle handle { atlas, xform, tex, colors, BlendMode::COLOR_BURN, samplingOptions,
        hasCullRect, cullRect, paintHandle };
    DrawAtlasOpItem opItem { *drawCmdList, &handle };
    opItem.atlas_ = std::make_shared<Image>();
    opItem.Marshalling(*drawCmdList);

    Canvas canvas;
    Rect rect;
    opItem.Playback(&canvas, &rect);
    opItem.atlas_ = nullptr;
    opItem.Playback(&canvas, &rect);

    std::string outStr;
    opItem.DumpItems(outStr);
    ASSERT_TRUE(!outStr.empty());

    DrawAtlasOpItem::SetBaseCallback(nullptr);
    opItem.Unmarshalling(*drawCmdList, &handle);
}

/**
 * @tc.name: DrawTextBlobOpItem001
 * @tc.desc: Test functions for DrawTextBlobOpItem
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, DrawTextBlobOpItem001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    Font font;
    auto textBlob = TextBlob::MakeFromString("11", font, TextEncoding::UTF8);
    Paint paint;
    auto space = std::make_shared<ColorSpace>();
    Color4f color;
    color.alphaF_ = 0;
    color.blueF_ = 1;
    paint.SetColor(color, space);
    DrawTextBlobOpItem opItem{textBlob.get(), 0, 0, paint};
    opItem.Marshalling(*drawCmdList);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(1, 10); // 1: width, 10: height
    Rect rect;
    opItem.Playback(recordingCanvas.get(), &rect);
    Canvas canvas;
    opItem.GenerateCachedOpItem(&canvas);
    auto recordingCanvas2 = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    opItem.Playback(recordingCanvas2.get(), &rect);
    opItem.DrawHighContrast(&canvas);
    opItem.DrawHighContrastEnabled(&canvas);

    textBlob->SetTextContrast(TextContrast::ENABLE_CONTRAST);
    opItem.Playback(recordingCanvas2.get(), &rect);

    textBlob->SetTextContrast(TextContrast::ENABLE_CONTRAST);
    opItem.Playback(recordingCanvas2.get(), &rect);

    DrawTextBlobOpItem::ConstructorHandle::GenerateCachedOpItem(*drawCmdList, nullptr, 0, 0, paint);
    DrawTextBlobOpItem::ConstructorHandle::GenerateCachedOpItem(*drawCmdList, textBlob.get(), 0, 0, paint);
    TextBlob textBlob2{nullptr};
    DrawTextBlobOpItem::ConstructorHandle::GenerateCachedOpItem(*drawCmdList, &textBlob2, 0, 0, paint);

    auto opDataHandle = CmdListHelper::AddTextBlobToCmdList(*drawCmdList, textBlob.get());
    opDataHandle.offset = 2;
    opDataHandle.size = 10;
    uint64_t globalUniqueId = 0;
    PaintHandle paintHandle;
    DrawTextBlobOpItem::ConstructorHandle handler{opDataHandle, globalUniqueId, 10, 10, paintHandle}; // 10: x, y
    handler.GenerateCachedOpItem(*drawCmdList, &canvas);
}

/**
 * @tc.name: DrawTextBlobOpItem002
 * @tc.desc: Test functions GetOffScreenSurfaceAndCanvas for DrawTextBlobOpItem
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, DrawTextBlobOpItem002, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    Font font;
    auto textBlob = TextBlob::MakeFromString("12", font, TextEncoding::UTF8);
    Paint paint;
    DrawTextBlobOpItem opItem { textBlob.get(), 0, 0, paint };
    Canvas canvas;
    std::shared_ptr<Drawing::Surface> offScreenSurface;
    std::shared_ptr<Canvas> offScreenCanvas;
    auto ret = opItem.GetOffScreenSurfaceAndCanvas(canvas, offScreenSurface, offScreenCanvas);
    ASSERT_TRUE(canvas.GetSurface() == nullptr);
    ASSERT_TRUE(textBlob->Bounds() != nullptr);
    ASSERT_FALSE(ret);
    DrawCmdTestCanvas canvers1;
    auto surface = std::make_shared<Drawing::Surface>();
    canvers1.SetSurface(surface.get());
    ASSERT_TRUE(canvers1.GetSurface() != nullptr);
    ret = opItem.GetOffScreenSurfaceAndCanvas(canvas, offScreenSurface, offScreenCanvas);
    ASSERT_TRUE(offScreenSurface == nullptr);
}

/**
 * @tc.name: IsHighContrastEnableTest
 * @tc.desc: Test functions for IsHighContrastEnableTest
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, IsHighContrastEnableTest, TestSize.Level1)
{
    Font font;
    auto textBlob = TextBlob::MakeFromString("11", font, TextEncoding::UTF8);
    Paint paint;
    DrawTextBlobOpItem opItem{textBlob.get(), 0, 0, paint};

    auto recordingCanvas = std::make_shared<RecordingCanvas>(1, 10);
    TextContrast textContrast = TextContrast::FOLLOW_SYSTEM;
    EXPECT_EQ(opItem.IsHighContrastEnable(recordingCanvas.get(), textContrast),
        recordingCanvas.get()->isHighContrastEnabled());

    textContrast = TextContrast::DISABLE_CONTRAST;
    EXPECT_FALSE(opItem.IsHighContrastEnable(recordingCanvas.get(), textContrast));

    textContrast = TextContrast::ENABLE_CONTRAST;
    EXPECT_TRUE(opItem.IsHighContrastEnable(recordingCanvas.get(), textContrast));
}

/**
 * @tc.name: DrawCmdList002
 * @tc.desc: Test function for DrawCmdList
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, DrawCmdList002, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    ColorQuad color = 0xFF000000;
    drawCmdList->AddDrawOp<DrawColorOpItem::ConstructorHandle>(color, BlendMode::SRC_OVER);
    EXPECT_TRUE(drawCmdList->IsEmpty());
    drawCmdList->SetIsCache(true);
    EXPECT_TRUE(drawCmdList->GetIsCache());
    drawCmdList->SetCachedHighContrast(true);
    EXPECT_TRUE(drawCmdList->GetCachedHighContrast());
    EXPECT_TRUE(drawCmdList->GetOpItemSize() >= 0);
    std::string s = "";
    s = drawCmdList->GetOpsWithDesc();
    drawCmdList->ClearOp();
    delete drawCmdList;

    auto drawCmdList2 = new DrawCmdList(
        10, 10, DrawCmdList::UnmarshalMode::IMMEDIATE); // 10: width, height
    EXPECT_TRUE(drawCmdList2->IsEmpty());
    EXPECT_TRUE(drawCmdList2->GetOpItemSize() >= 0);
    drawCmdList2->AddDrawOp(nullptr);
    EXPECT_TRUE(drawCmdList2->IsEmpty());
    delete drawCmdList2;
}

/**
 * @tc.name: GetOpsWithDesc001
 * @tc.desc: Test GetOpsWithDesc
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, GetOpsWithDesc001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    ColorQuad color = 0xFF000000;
    drawCmdList->AddDrawOp<DrawColorOpItem::ConstructorHandle>(color, BlendMode::SRC_OVER);
    drawCmdList->AddDrawOp<DrawColorOpItem::ConstructorHandle>(color, BlendMode::DST_OVER);

    std::string s = "";
    s = drawCmdList->GetOpsWithDesc();
    drawCmdList->ClearOp();
    EXPECT_TRUE(drawCmdList->IsEmpty());
    delete drawCmdList;
}

/**
 * @tc.name: MarshallingDrawOps001
 * @tc.desc: Test MarshallingDrawOps
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, MarshallingDrawOps001, TestSize.Level1)
{
    auto drawCmdList1 = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList1->MarshallingDrawOps();
    drawCmdList1->UnmarshallingDrawOps();
    drawCmdList1->AddDrawOp(nullptr);
    delete drawCmdList1;

    auto drawCmdList2 = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    drawCmdList2->MarshallingDrawOps();
    drawCmdList2->UnmarshallingDrawOps();
    ColorQuad color = 0xFF000000;
    drawCmdList2->AddDrawOp<DrawColorOpItem::ConstructorHandle>(color, BlendMode::SRC_OVER);
    EXPECT_TRUE(drawCmdList2->IsEmpty());
    delete drawCmdList2;
}

/**
 * @tc.name: Playback001
 * @tc.desc: Test Playback for DrawCmdList
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, Playback001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->SetWidth(0);
    Canvas canvas;
    Rect rect;
    drawCmdList->Playback(canvas, &rect);
    drawCmdList->SetWidth(10);
    drawCmdList->SetHeight(10);
    drawCmdList->SetCachedHighContrast(false);
    drawCmdList->Playback(canvas, &rect);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    drawCmdList->Playback(*recordingCanvas, &rect);
    drawCmdList->SetIsCache(true);
    drawCmdList->SetCachedHighContrast(false);
    drawCmdList->Playback(canvas, &rect);
    drawCmdList->SetCachedHighContrast(true);
    drawCmdList->Playback(canvas, &rect);
    delete drawCmdList;

    auto drawCmdList2 = new DrawCmdList(10, 10, DrawCmdList::UnmarshalMode::DEFERRED);
    drawCmdList2->Playback(*recordingCanvas, &rect);
    delete drawCmdList2;

    auto drawCmdList3 = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    drawCmdList3->Playback(*recordingCanvas, &rect);
    EXPECT_TRUE(drawCmdList3->IsEmpty());
}

/**
 * @tc.name: GenerateCache001
 * @tc.desc: Test GenerateCache for DrawCmdList
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, GenerateCache001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->SetIsCache(true);
    auto recordingCanvas = std::make_shared<RecordingCanvas>(10, 10); // 10: width, height
    Rect rect;
    drawCmdList->Playback(*recordingCanvas, &rect);
    drawCmdList->GenerateCache(recordingCanvas.get(), &rect);
    drawCmdList->SetIsCache(false);
    drawCmdList->GenerateCache(recordingCanvas.get(), &rect);
    Brush brush;
    drawCmdList->AddDrawOp(std::make_shared<DrawBackgroundOpItem>(brush));
    Font font;
    auto textBlob = TextBlob::MakeFromString("11", font, TextEncoding::UTF8);
    Paint paint;
    auto space = std::make_shared<ColorSpace>();
    Color4f color;
    color.alphaF_ = 0;
    color.blueF_ = 1;
    paint.SetColor(color, space);
    auto opItem = std::make_shared<DrawTextBlobOpItem>(textBlob.get(), 0, 0, paint);
    drawCmdList->AddDrawOp(opItem);
    drawCmdList->GenerateCache(recordingCanvas.get(), &rect);
    drawCmdList->Playback(*recordingCanvas, &rect);
    drawCmdList->MarshallingDrawOps();
    drawCmdList->AddDrawOp(nullptr);
    drawCmdList->UnmarshallingDrawOps();
    delete drawCmdList;
    
    auto drawCmdList2 = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    drawCmdList2->SetIsCache(false);
    drawCmdList2->GenerateCache(recordingCanvas.get(), &rect);
    ColorQuad color2 = 0xFF000000;
    drawCmdList2->AddDrawOp<DrawColorOpItem::ConstructorHandle>(color2, BlendMode::SRC_OVER);
    drawCmdList2->GenerateCache(recordingCanvas.get(), &rect);
    EXPECT_TRUE(drawCmdList2->IsEmpty());
    delete drawCmdList2;
}

/**
 * @tc.name: UpdateNodeIdToPicture001
 * @tc.desc: Test UpdateNodeIdToPicture
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, UpdateNodeIdToPicture001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    EXPECT_TRUE(drawCmdList != nullptr);
    NodeId nodeId = 100;
    drawCmdList->AddDrawOp(nullptr);
    Brush brush;
    drawCmdList->AddDrawOp(std::make_shared<DrawBackgroundOpItem>(brush));
    EXPECT_TRUE(!drawCmdList->IsEmpty());
    drawCmdList->UpdateNodeIdToPicture(nodeId);
}

/**
 * @tc.name: MaskCmdList001
 * @tc.desc: Test functions for MaskCmdList
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, MaskCmdList001, TestSize.Level1)
{
    Drawing::CmdListData listData;
    auto maskCmdList = MaskCmdList::CreateFromData(listData, true);
    EXPECT_TRUE(maskCmdList != nullptr);
    auto path = std::make_shared<Path>();
    Brush brush;
    maskCmdList->Playback(path, brush);
    Pen pen;
    maskCmdList->Playback(path, pen, brush);
    EXPECT_FALSE(path->IsValid());

    auto maskCmdList2 = MaskCmdList::CreateFromData(listData, false);
    EXPECT_TRUE(maskCmdList2 != nullptr);
    maskCmdList2->Playback(path, brush);
    maskCmdList2->Playback(path, pen, brush);
    EXPECT_FALSE(path->IsValid());
}

#ifdef ROSEN_OHOS
/**
 * @tc.name: SurfaceBuffer001
 * @tc.desc: Test SurfaceBuffer
 * @tc.type: FUNC
 * @tc.require: I9120P
 */
HWTEST_F(DrawCmdTest, SurfaceBuffer001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    std::shared_ptr<SurfaceBufferEntry> surfaceBufferEntry;
    drawCmdList->AddSurfaceBufferEntry(surfaceBufferEntry);
    EXPECT_TRUE(drawCmdList->GetSurfaceBufferEntry(0) == nullptr);
    EXPECT_TRUE(drawCmdList->GetSurfaceBufferEntry(10) == nullptr);
    std::vector<std::shared_ptr<SurfaceBufferEntry>> surfaceBufferVecEntry;
    uint32_t surfaceBufferSize = drawCmdList->GetAllSurfaceBufferEntry(surfaceBufferVecEntry);
    EXPECT_TRUE(surfaceBufferSize >= 0);
}
#endif

/**
 * @tc.name: SetNoNeedUICapturedTest
 * @tc.desc: Test SetNoNeedUICaptured
 * @tc.type: FUNC
 * @tc.require: IBDGY3
 */
HWTEST_F(DrawCmdTest, SetNoNeedUICapturedTest, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    drawCmdList->SetNoNeedUICaptured(true);
    ASSERT_TRUE(drawCmdList->GetNoNeedUICaptured());
}

/**
 * @tc.name: ClipAdaptiveRoundRectOpItem_Marshalling001
 * @tc.desc: Test ClipAdaptiveRoundRectOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ClipAdaptiveRoundRectOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    ClipAdaptiveRoundRectOpItem::ConstructorHandle handle { { 0, 0 } };
    ASSERT_TRUE(drawCmdList != nullptr);
    ClipAdaptiveRoundRectOpItem opItem { *drawCmdList, &handle };
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: DiscardOpItem_Marshalling001
 * @tc.desc: Test DiscardOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, DiscardOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({nullptr, 0}, false);
    DiscardOpItem opItem;
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: RestoreOpItem_Marshalling001
 * @tc.desc: Test RestoreOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, RestoreOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    RestoreOpItem opItem;
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: SaveOpItem_Marshalling001
 * @tc.desc: Test SaveOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, SaveOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    SaveOpItem opItem;
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ClearOpItem_Marshalling001
 * @tc.desc: Test ClearOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ClearOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    ColorQuad colorQuad { 0 };
    ClearOpItem::ConstructorHandle handle { colorQuad };
    ClearOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: FlushOpItem_Marshalling001
 * @tc.desc: Test FlushOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, FlushOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    FlushOpItem opItem;
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ShearOpItem_Marshalling001
 * @tc.desc: Test ShearOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ShearOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    ShearOpItem::ConstructorHandle handle { 10.f, 10.f }; // 10.f means ShearOpItem location
    ShearOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: RotateOpItem_Marshalling001
 * @tc.desc: Test RotateOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, RotateOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    // 90.f means degree, 10.f means RotateOpItem location
    RotateOpItem::ConstructorHandle handle { 90.f, 10.f, 10.f };
    RotateOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ScaleOpItem_Marshalling001
 * @tc.desc: Test ScaleOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ScaleOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    ScaleOpItem::ConstructorHandle handle { 10.f, 10.f }; // 10.f means ScaleOpItem value
    ScaleOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: TranslateOpItem_Marshalling001
 * @tc.desc: Test TranslateOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, TranslateOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    TranslateOpItem::ConstructorHandle handle { 10.f, 10.f }; // 10.f means TranslateOpItem value
    TranslateOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ConcatMatrixOpItem_Marshalling001
 * @tc.desc: Test ConcatMatrixOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ConcatMatrixOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    // 20.9f, 15.8f, 80.8f, 60.6f, 2.4f, 99.9f, 60.5f, 60.1f, 90.5f means the value for a 3x3 float type matrix
    Matrix::Buffer matrixBuffer { 20.9f, 15.8f, 80.8f, 60.6f, 2.4f, 99.9f, 60.5f, 60.1f, 90.5f };
    ConcatMatrixOpItem::ConstructorHandle handle { matrixBuffer };
    ConcatMatrixOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ResetMatrixOpItem_Marshalling001
 * @tc.desc: Test ResetMatrixOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ResetMatrixOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({nullptr, 0}, false);
    ResetMatrixOpItem opItem;
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: SetMatrixOpItem_Marshalling001
 * @tc.desc: Test SetMatrixOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, SetMatrixOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({ nullptr, 0 }, false);
    // 20.9f, 15.8f, 80.8f, 60.6f, 2.4f, 99.9f, 60.5f, 60.1f, 90.5f means the value for a 3x3 float type matrix
    Matrix::Buffer matrixBuffer { 20.9f, 15.8f, 80.8f, 60.6f, 2.4f, 99.9f, 60.5f, 60.1f, 90.5f };
    SetMatrixOpItem::ConstructorHandle handle { matrixBuffer };
    SetMatrixOpItem opItem { &handle };
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ClipRegionOpItem_Marshalling001
 * @tc.desc: Test ClipRegionOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ClipRegionOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({nullptr, 0}, false);
    ClipOp clipOp = ClipOp::DIFFERENCE;
    Region region;
    ClipRegionOpItem opItem{region, clipOp};
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ClipRoundRectOpItem_Marshalling001
 * @tc.desc: Test ClipRoundRectOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ClipRoundRectOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({nullptr, 0}, false);
    RoundRect rect;
    ClipOp clipOp = ClipOp::INTERSECT;
    ClipRoundRectOpItem::ConstructorHandle handle{rect, clipOp, false};
    ClipRoundRectOpItem opItem{&handle};
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ClipIRectOpItem_Marshalling001
 * @tc.desc: Test ClipIRectOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ClipIRectOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({nullptr, 0}, false);
    RectI rect;
    ClipOp clipOp = ClipOp::DIFFERENCE;
    ClipIRectOpItem::ConstructorHandle handle{rect, clipOp};
    ClipIRectOpItem opItem{&handle};
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}

/**
 * @tc.name: ClipRectOpItem_Marshalling001
 * @tc.desc: Test ClipRectOpItem_Marshalling
 * @tc.type: FUNC
 * @tc.require: IAKWZL
 */
HWTEST_F(DrawCmdTest, ClipRectOpItem_Marshalling001, TestSize.Level1)
{
    auto drawCmdList = DrawCmdList::CreateFromData({nullptr, 0}, false);
    RectI rect;
    ClipOp clipOp = ClipOp::DIFFERENCE;
    ClipRectOpItem::ConstructorHandle handle{rect, clipOp, false};
    ClipRectOpItem opItem{&handle};
    ASSERT_TRUE(drawCmdList != nullptr);
    opItem.Marshalling(*drawCmdList);
    EXPECT_EQ(drawCmdList->opCnt_, 1);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS