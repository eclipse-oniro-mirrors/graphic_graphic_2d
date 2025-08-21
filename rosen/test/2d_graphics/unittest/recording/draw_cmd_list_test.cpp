/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "draw/brush.h"
#include "image/image.h"
#include "pipeline/rs_draw_cmd.h"
#include "recording/cmd_list_helper.h"
#include "recording/draw_cmd.h"
#include "recording/draw_cmd_list.h"
#include "utils/vertices.h"
#include "pixel_map.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
#define TEST_MEM_SIZE 10
#define TEST_INVALIED_ID 9999
class DrawCmdListTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DrawCmdListTest::SetUpTestCase() {}
void DrawCmdListTest::TearDownTestCase() {}
void DrawCmdListTest::SetUp() {}
void DrawCmdListTest::TearDown() {}

/**
 * @tc.name: GetOpsWithDesc001
 * @tc.desc: Test the GetOpsWithDesc function.
 * @tc.type: FUNC
 * @tc.require: IBJ4VQ
 */
HWTEST_F(DrawCmdListTest, GetOpsWithDesc001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    drawCmdList->drawOpItems_.emplace_back(nullptr);
    Brush brush;
    drawCmdList->drawOpItems_.emplace_back(std::make_shared<DrawBackgroundOpItem>(brush));
    std::string s = "";
    s = drawCmdList->GetOpsWithDesc();
    EXPECT_TRUE(drawCmdList->drawOpItems_.size() == 2); // 2 for test
    delete drawCmdList;
}

/**
 * @tc.name: Dump002
 * @tc.desc: Test the Dump function.
 * @tc.type: FUNC
 * @tc.require: IBJ4VQ
 */
HWTEST_F(DrawCmdListTest, Dump002, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    drawCmdList->drawOpItems_.emplace_back(nullptr);
    Brush brush;
    drawCmdList->drawOpItems_.emplace_back(std::make_shared<DrawBackgroundOpItem>(brush));
    std::string s = "";
    drawCmdList->Dump(s);
    EXPECT_TRUE(drawCmdList->drawOpItems_.size() == 2); // 2 for test
    delete drawCmdList;
}

/**
 * @tc.name: MarshallingDrawOps003
 * @tc.desc: Test the MarshallingDrawOps function.
 * @tc.type: FUNC
 * @tc.require: IBJ4VQ
 */
HWTEST_F(DrawCmdListTest, MarshallingDrawOps003, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    drawCmdList->performanceCaculateOpType_ = 1; // 1 for test
    drawCmdList->MarshallingDrawOps();
    drawCmdList->UnmarshallingDrawOps();
    EXPECT_TRUE(drawCmdList->performanceCaculateOpType_ == 1);
    delete drawCmdList;
}

/**
 * @tc.name: Playback004
 * @tc.desc: Test the Playback function.
 * @tc.type: FUNC
 * @tc.require: IBJ4VQ
 */
HWTEST_F(DrawCmdListTest, Playback004, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->SetWidth(0);
    Canvas canvas;
    Rect rect;
    drawCmdList->performanceCaculateOpType_ = 1; // 1 for test
    drawCmdList->Playback(canvas, &rect);
    EXPECT_TRUE(drawCmdList->performanceCaculateOpType_ == 1);
    delete drawCmdList;
}

/**
 * @tc.name: GenerateCacheByVector005
 * @tc.desc: Test the GenerateCacheByVector function.
 * @tc.type: FUNC
 * @tc.require: IBJ4VQ
 */
HWTEST_F(DrawCmdListTest, GenerateCacheByVector005, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    Brush brush;
    drawCmdList->drawOpItems_.emplace_back(std::make_shared<DrawBackgroundOpItem>(brush));
    Font font;
    auto textBlob = TextBlob::MakeFromString("11", font, TextEncoding::UTF8);
    Paint paint;
    auto opItem = std::make_shared<DrawTextBlobOpItem>(textBlob.get(), 0, 0, paint);
    drawCmdList->drawOpItems_.emplace_back(opItem);
    Canvas canvas;
    Rect rect;
    drawCmdList->GenerateCacheByVector(&canvas, &rect);
    EXPECT_TRUE(drawCmdList->drawOpItems_.size() == 2); // 2 for test
    delete drawCmdList;
}

/**
 * @tc.name: GenerateCacheByBuffer006
 * @tc.desc: Test the GenerateCacheByBuffer function.
 * @tc.type: FUNC
 * @tc.require: IBJ4VQ
 */
HWTEST_F(DrawCmdListTest, GenerateCacheByBuffer006, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() <= drawCmdList->offset_);
    Canvas canvas;
    Rect rect;
    drawCmdList->GenerateCacheByBuffer(&canvas, &rect);
    EXPECT_FALSE(drawCmdList->isCached_);
    delete drawCmdList;
}

/**
 * @tc.name: GetBounds001
 * @tc.desc: Test the GetBounds function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, GetBounds001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() <= drawCmdList->offset_);
    auto ret = drawCmdList->UnmarshallingDrawOpsSimple(drawCmdList->drawOpItems_, drawCmdList->lastOpGenSize_);
    EXPECT_EQ(ret, false);
    Rect rect;
    drawCmdList->GetBounds(rect);
    EXPECT_EQ(rect.IsValid(), false);
    delete drawCmdList;
}

/**
 * @tc.name: GetBounds002
 * @tc.desc: Test the GetBounds function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, GetBounds002, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->opAllocator_.size_ = drawCmdList->offset_ + 1;
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() > drawCmdList->offset_);
    auto ret = drawCmdList->UnmarshallingDrawOpsSimple(drawCmdList->drawOpItems_, drawCmdList->lastOpGenSize_);
    EXPECT_EQ(ret, true);
    Rect rect;
    drawCmdList->GetBounds(rect);
    delete drawCmdList;
}

/**
 * @tc.name: GetBounds003
 * @tc.desc: Test the GetBounds function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, GetBounds003, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->opAllocator_.size_ = drawCmdList->offset_ + 1;
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() > drawCmdList->offset_);
    drawCmdList->lastOpGenSize_ = drawCmdList->opAllocator_.GetSize();
    Brush brush;
    drawCmdList->drawOpItems_.emplace_back(std::make_shared<DrawBackgroundOpItem>(brush));
    Rect rect = Rect(0.0f, 0.0f, 100.0f, 100.0f);
    auto opItem = std::make_shared<HybridRenderPixelMapSizeOpItem>(rect.GetWidth(), rect.GetHeight());
    drawCmdList->drawOpItems_.emplace_back(opItem);
    auto ret = drawCmdList->UnmarshallingDrawOpsSimple(drawCmdList->drawOpItems_, drawCmdList->lastOpGenSize_);
    EXPECT_EQ(ret, true);
    Rect rectGet;
    drawCmdList->GetBounds(rectGet);
    EXPECT_EQ(rect, rectGet);
    delete drawCmdList;
}

/**
 * @tc.name: GetBounds004
 * @tc.desc: Test the GetBounds function.
 * @tc.type: FUNC
 * @tc.require: IC8J12
 */
HWTEST_F(DrawCmdListTest, GetBounds004, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->drawOpItems_.emplace_back(nullptr);
    Rect rect;
    drawCmdList->GetBounds(rect);
    EXPECT_EQ(rect.IsValid(), false);
    delete drawCmdList;
}

/**
 * @tc.name: IsHybridRenderEnabled001
 * @tc.desc: Test the IsHybridRenderEnabled function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, IsHybridRenderEnabled001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() <= drawCmdList->offset_);
    drawCmdList->hybridRenderType_ = DrawCmdList::HybridRenderType::CANVAS;
    auto ret = drawCmdList->IsHybridRenderEnabled(0, 0);
    EXPECT_EQ(ret, true);
    delete drawCmdList;
}

/**
 * @tc.name: IsHybridRenderEnabled002
 * @tc.desc: Test the IsHybridRenderEnabled function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, IsHybridRenderEnabled002, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->opAllocator_.size_ = drawCmdList->offset_ + 1;
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() > drawCmdList->offset_);
    auto ret = drawCmdList->IsHybridRenderEnabled(INT_MAX, INT_MAX);
    EXPECT_EQ(ret, true);
    delete drawCmdList;
}

/**
 * @tc.name: IsHybridRenderEnabled003
 * @tc.desc: Test the IsHybridRenderEnabled function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, IsHybridRenderEnabled003, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->opAllocator_.size_ = drawCmdList->offset_ + 1;
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() > drawCmdList->offset_);
    drawCmdList->lastOpGenSize_ = drawCmdList->opAllocator_.GetSize();
    Brush brush;
    drawCmdList->drawOpItems_.emplace_back(std::make_shared<DrawBackgroundOpItem>(brush));
    Rect rect = Rect(0.0f, 0.0f, 100.0f, 100.0f);
    auto opItem = std::make_shared<HybridRenderPixelMapSizeOpItem>(rect.GetWidth(), rect.GetHeight());
    drawCmdList->drawOpItems_.emplace_back(opItem);
    auto ret = drawCmdList->IsHybridRenderEnabled(INT_MAX, INT_MAX);
    EXPECT_EQ(ret, true);
    delete drawCmdList;
}

/**
 * @tc.name: IsHybridRenderEnabled004
 * @tc.desc: Test the IsHybridRenderEnabled function.
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, IsHybridRenderEnabled004, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->opAllocator_.size_ = drawCmdList->offset_ + 1;
    EXPECT_TRUE(drawCmdList->opAllocator_.GetSize() > drawCmdList->offset_);
    drawCmdList->width_ = 5001;
    drawCmdList->height_ = 1000;
    auto ret = drawCmdList->IsHybridRenderEnabled(5000, 5000);
    EXPECT_EQ(ret, false);
    drawCmdList->width_ = 5001;
    drawCmdList->height_ = 5000;
    ret = drawCmdList->IsHybridRenderEnabled(5000, 5000);
    EXPECT_EQ(ret, false);
    drawCmdList->width_ = 1000;
    drawCmdList->height_ = 5001;
    ret = drawCmdList->IsHybridRenderEnabled(5000, 5000);
    EXPECT_EQ(ret, false);
    drawCmdList->width_ = -1;
    drawCmdList->height_ = 5001;
    ret = drawCmdList->IsHybridRenderEnabled(5000, 5000);
    EXPECT_EQ(ret, false);
    drawCmdList->width_ = 5001;
    drawCmdList->height_ = -1;
    ret = drawCmdList->IsHybridRenderEnabled(5000, 5000);
    EXPECT_EQ(ret, false);
    drawCmdList->width_ = -1;
    drawCmdList->height_ = -1;
    ret = drawCmdList->IsHybridRenderEnabled(5000, 5000);
    EXPECT_EQ(ret, true);
    delete drawCmdList;
}

/**
 * @tc.name: ProfilerMarshallingDrawOps
 * @tc.desc: Test ProfilerMarshallingDrawOps
 * @tc.type: FUNC
 * @tc.require: IC2UAC
 */
HWTEST_F(DrawCmdListTest, ProfilerMarshallingDrawOps, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    auto secondDrawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::DEFERRED);
    Brush brush;
    drawCmdList->drawOpItems_.emplace_back(std::make_shared<DrawBackgroundOpItem>(brush));
    EXPECT_EQ(drawCmdList->drawOpItems_.size(), 1);
    drawCmdList->ProfilerMarshallingDrawOps(secondDrawCmdList);
    EXPECT_TRUE(secondDrawCmdList->lastOpItemOffset_.has_value());
    delete drawCmdList;
    delete secondDrawCmdList;
}

/**
 * @tc.name: ProfilerMarshallingDrawOpsDoesNotCopyImmediateCmdList
 * @tc.desc: ProfilerMarshallingDrawOps does not copy drawOpItems_ when mode_ = IMMEDIATE
 * @tc.type: FUNC
 */
HWTEST_F(DrawCmdListTest, ProfilerMarshallingDrawOpsDoesNotCopyImmediateCmdList, TestSize.Level1)
{
    DrawCmdList src(DrawCmdList::UnmarshalMode::IMMEDIATE);
    src.drawOpItems_.emplace_back(std::make_shared<DrawWithPaintOpItem>(Drawing::Paint(), 0));
    DrawCmdList dst;
    src.ProfilerMarshallingDrawOps(&dst, true);
    src.ProfilerMarshallingDrawOps(&dst, false);
    EXPECT_TRUE(dst.drawOpItems_.empty());
}

/**
 * @tc.name: ProfilerMarshallingDrawOpsCopiesImageOpsWhenIncludeImageOpsIsTrue
 * @tc.desc: ProfilerMarshallingDrawOps copies image draw ops when includeImageOps = true
 * @tc.type: FUNC
 */
HWTEST_F(DrawCmdListTest, ProfilerMarshallingDrawOpsCopiesImageOpsWhenIncludeImageOpsIsTrue, TestSize.Level1)
{
    constexpr auto includeImageOps = true;
    const auto drawOp =
        std::make_shared<DrawImageOpItem>(Drawing::Image(), 0, 0, Drawing::SamplingOptions(), Drawing::Paint());
    DrawCmdList src(DrawCmdList::UnmarshalMode::DEFERRED);
    src.drawOpItems_.push_back(drawOp);
    DrawCmdList dst;
    src.ProfilerMarshallingDrawOps(&dst, includeImageOps);
    EXPECT_TRUE(dst.drawOpItems_.empty());
}

/**
 * @tc.name: ProfilerMarshallingDrawOpsDoesNotCopyImageOpsWhenIncludeImageOpsIsFalse
 * @tc.desc: ProfilerMarshallingDrawOps does not copy image draw ops when includeImageOps = false
 * @tc.type: FUNC
 */
HWTEST_F(DrawCmdListTest, ProfilerMarshallingDrawOpsDoesNotCopyImageOpsWhenIncludeImageOpsIsFalse, TestSize.Level1)
{
    auto image = Drawing::Image();
    auto brush = Drawing::Brush();
    constexpr auto includeImageOps = false;
    const auto drawImageOp =
        std::make_shared<DrawImageOpItem>(Drawing::Image(), 0, 0, Drawing::SamplingOptions(), Drawing::Paint());

    const auto drawImageRectOp = std::make_shared<DrawImageRectOpItem>(Drawing::Image(), Drawing::Rect(0, 10, 10, 0),
        Drawing::Rect(0, 10, 10, 0), Drawing::SamplingOptions(),
        Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT, Drawing::Paint());
    const auto drawImageLatticeOp = std::make_shared<DrawImageLatticeOpItem>(
        &image, Drawing::Lattice(), Rect(0, 10, 10, 0), Drawing::FilterMode::LINEAR, Drawing::Paint());
    const auto drawImageNineOp = std::make_shared<DrawImageNineOpItem>(
        &image, Drawing::RectI(0, 10, 10, 0), Drawing::RectI(0, 10, 10, 0), Drawing::FilterMode::LINEAR, &brush);
    const auto drawAtlasOp = std::make_shared<DrawAtlasOpItem>(&image, std::vector<Drawing::RSXform>(),
        std::vector<Drawing::Rect>(), std::vector<Drawing::ColorQuad>(), Drawing::BlendMode::DARKEN,
        Drawing::SamplingOptions(), false, Drawing::Rect(0, 10, 10, 0), Drawing::Paint());
    const auto drawHybridRenderPixelMapSizeOp = std::make_shared<HybridRenderPixelMapSizeOpItem>(100, 200);
    const auto drawImageWithParmOp = std::make_shared<DrawImageWithParmOpItem>(std::make_shared<Drawing::Image>(),
        std::make_shared<Drawing::Data>(), Drawing::AdaptiveImageInfo(), Drawing::SamplingOptions(), Drawing::Paint());
    const auto drawPixelmapWithParmOp = std::make_shared<DrawPixelMapWithParmOpItem>(
        std::make_shared<Media::PixelMap>(), Drawing::AdaptiveImageInfo(),
        Drawing::SamplingOptions(), Drawing::Paint());
    const auto drawPixelmapRectOp = std::make_shared<DrawPixelMapRectOpItem>(std::make_shared<Media::PixelMap>(),
        Drawing::Rect(0, 10, 10, 0), Drawing::Rect(0, 10, 10, 0), Drawing::SamplingOptions(),
        Drawing::SrcRectConstraint::FAST_SRC_RECT_CONSTRAINT, Drawing::Paint());

    DrawCmdList src(DrawCmdList::UnmarshalMode::DEFERRED);
    src.drawOpItems_.push_back(drawImageOp);
    src.drawOpItems_.push_back(drawImageRectOp);
    src.drawOpItems_.push_back(drawImageLatticeOp);
    src.drawOpItems_.push_back(drawImageNineOp);
    src.drawOpItems_.push_back(drawAtlasOp);
    src.drawOpItems_.push_back(drawHybridRenderPixelMapSizeOp);
    src.drawOpItems_.push_back(drawImageWithParmOp);
    src.drawOpItems_.push_back(drawPixelmapWithParmOp);
    src.drawOpItems_.push_back(drawPixelmapRectOp);

    DrawCmdList dst;
    src.ProfilerMarshallingDrawOps(&dst, includeImageOps);
    EXPECT_TRUE(dst.drawOpItems_.empty());
}

/**
 * @tc.name: SetIsReplayMode
 * @tc.desc: Test SetIsReplayMode
 * @tc.require:
 */
HWTEST_F(DrawCmdListTest, SetIsReplayMode, Level1)
{
    auto drawCmdList = new DrawCmdList();
    drawCmdList->SetIsReplayMode(true);
    EXPECT_TRUE(drawCmdList->isReplayMode);
    drawCmdList->SetIsReplayMode(false);
    EXPECT_FALSE(drawCmdList->isReplayMode);
    delete drawCmdList;
}

/**
 * @tc.name: Dump003
 * @tc.desc: Test the Dump function.
 * @tc.type: UnmarshallingDrawOpsSimple
 */
HWTEST_F(DrawCmdListTest, Dump003, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList(DrawCmdList::UnmarshalMode::IMMEDIATE);
    drawCmdList->opAllocator_.size_ = drawCmdList->offset_ + 1;
    EXPECT_FALSE(drawCmdList->IsEmpty());
    EXPECT_TRUE(drawCmdList->drawOpItems_.empty());
    
    std::string out;
    drawCmdList->Dump(out);
    EXPECT_TRUE(out.empty());
    delete drawCmdList;
}

/**
 * @tc.name: GetCmdlistDrawRegion001
 * @tc.desc: Test the GetCmdlistDrawRegion function.
 * @tc.type: FUNC
 * @tc.require: ICI6YB
 */
HWTEST_F(DrawCmdListTest, GetCmdlistDrawRegion001, TestSize.Level1)
{
    auto drawCmdList = new DrawCmdList();
    EXPECT_TRUE(drawCmdList->GetCmdlistDrawRegion().IsEmpty());

    drawCmdList->drawOpItems_.emplace_back(nullptr);
    EXPECT_TRUE(drawCmdList->GetCmdlistDrawRegion().IsEmpty());
    delete drawCmdList;
}

/**
 * @tc.name: GetCmdlistDrawRegion002
 * @tc.desc: Test the GetCmdlistDrawRegion function.
 * @tc.type: FUNC
 * @tc.require: ICI6YB
 */
HWTEST_F(DrawCmdListTest, GetCmdlistDrawRegion002, TestSize.Level1)
{
    Path path;
    path.Offset(1.0f, 1.0f);
    Paint paint;
    DrawPathOpItem pathOpItem{path, paint};
    pathOpItem.path_->MoveTo(1.0f, 2.0f);
    pathOpItem.path_->LineTo(3.0f, 4.0f);
    ASSERT_TRUE(!(pathOpItem.GetOpItemCmdlistDrawRegion().IsEmpty()));

    auto pathOpItemPtr = std::make_shared<DrawPathOpItem>(pathOpItem);
    auto saveOpItemPtr = std::make_shared<SaveOpItem>();
    auto drawCmdList = new DrawCmdList();
    drawCmdList->drawOpItems_.emplace_back(pathOpItemPtr);
    drawCmdList->drawOpItems_.emplace_back(saveOpItemPtr);
    EXPECT_FALSE(drawCmdList->GetCmdlistDrawRegion().IsEmpty());

    auto fulshOpItemPtr = std::make_shared<FlushOpItem>();
    drawCmdList->drawOpItems_.emplace_back(fulshOpItemPtr);
    EXPECT_TRUE(drawCmdList->GetCmdlistDrawRegion().IsEmpty());
    delete drawCmdList;
}

// Mock Object class for testing
class MockDrawingObject : public Object {
public:
    MockDrawingObject() : Object(ObjectType::NO_TYPE, 0) {}

#ifdef ROSEN_OHOS
    bool Marshalling(Parcel& parcel) override
    {
        return true;
    }

    bool Unmarshalling(Parcel& parcel, bool& isValid, int32_t depth = 0) override
    {
        return true;
    }
#endif

    std::shared_ptr<void> GenerateBaseObject() override
    {
        return std::make_shared<int>(42); // Return a simple test object, random 42
    }
};

/**
 * @tc.name: GetDrawingObjectOutOfBounds001
 * @tc.desc: Test the GetDrawingObject function with index out of bounds
 * @tc.type: FUNC
 * @tc.require: AR000GGNV3
 * @tc.author:
 */
HWTEST_F(DrawCmdListTest, GetDrawingObjectOutOfBounds001, TestSize.Level1)
{
    auto drawCmdList = std::make_shared<DrawCmdList>(DrawCmdList::UnmarshalMode::IMMEDIATE);
    ASSERT_NE(drawCmdList, nullptr);

    // Test case 1: Empty drawingObjectVec_ - any index should return nullptr
    auto result1 = drawCmdList->GetDrawingObject(0);
    EXPECT_EQ(result1, nullptr); // index 0 >= size 0

    auto result2 = drawCmdList->GetDrawingObject(1);
    EXPECT_EQ(result2, nullptr); // index 1 >= size 0

    auto result3 = drawCmdList->GetDrawingObject(UINT32_MAX);
    EXPECT_EQ(result3, nullptr); // index UINT32_MAX >= size 0

    // Test case 2: Add one drawing object, then test boundary
    std::shared_ptr<Object> mockObject = std::make_shared<MockDrawingObject>();
    ASSERT_NE(mockObject, nullptr);

    uint32_t addedIndex = drawCmdList->AddDrawingObject(mockObject);
    EXPECT_EQ(addedIndex, 0); // First object should be at index 0

    // Valid index should work
    auto validResult = drawCmdList->GetDrawingObject(0);
    EXPECT_NE(validResult, nullptr);
    EXPECT_EQ(validResult, mockObject);

    // Test index equal to size (should fail)
    auto boundaryResult = drawCmdList->GetDrawingObject(1);
    EXPECT_EQ(boundaryResult, nullptr); // index 1 >= size 1

    // Test index greater than size (should fail)
    auto outOfBoundsResult1 = drawCmdList->GetDrawingObject(2);
    EXPECT_EQ(outOfBoundsResult1, nullptr); // index 2 >= size 1

    auto outOfBoundsResult2 = drawCmdList->GetDrawingObject(100);
    EXPECT_EQ(outOfBoundsResult2, nullptr); // index 100 >= size 1

    auto outOfBoundsResult3 = drawCmdList->GetDrawingObject(UINT32_MAX);
    EXPECT_EQ(outOfBoundsResult3, nullptr); // index UINT32_MAX >= size 1

    // Test case 3: Add multiple objects and test various boundary conditions
    std::shared_ptr<Object> mockObject2 = std::make_shared<MockDrawingObject>();
    std::shared_ptr<Object> mockObject3 = std::make_shared<MockDrawingObject>();

    uint32_t addedIndex2 = drawCmdList->AddDrawingObject(mockObject2);
    uint32_t addedIndex3 = drawCmdList->AddDrawingObject(mockObject3);

    EXPECT_EQ(addedIndex2, 1);
    EXPECT_EQ(addedIndex3, 2);

    // Valid indices should work
    EXPECT_EQ(drawCmdList->GetDrawingObject(0), mockObject);
    EXPECT_EQ(drawCmdList->GetDrawingObject(1), mockObject2);
    EXPECT_EQ(drawCmdList->GetDrawingObject(2), mockObject3);

    // Index equal to size should fail
    auto boundaryResult2 = drawCmdList->GetDrawingObject(3);
    EXPECT_EQ(boundaryResult2, nullptr); // index 3 >= size 3

    // Index greater than size should fail
    auto outOfBoundsResult4 = drawCmdList->GetDrawingObject(4);
    EXPECT_EQ(outOfBoundsResult4, nullptr); // index 4 >= size 3
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS