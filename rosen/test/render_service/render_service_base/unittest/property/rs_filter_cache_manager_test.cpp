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
#include <parameters.h>

#include "render/rs_filter_cache_manager.h"
#include "render/rs_drawing_filter.h"
#include "render/rs_filter.h"
#include "render/rs_kawase_blur_shader_filter.h"
#include "render/rs_magnifier_shader_filter.h"
#include "skia_adapter/skia_surface.h"
#include "skia_canvas.h"
#include "skia_surface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSFilterCacheManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSFilterCacheManagerTest::SetUpTestCase() {}
void RSFilterCacheManagerTest::TearDownTestCase() {}
void RSFilterCacheManagerTest::SetUp() {}
void RSFilterCacheManagerTest::TearDown() {}

/**
 * @tc.name: GetCacheStateTest
 * @tc.desc: test results of GetCacheState
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, GetCacheStateTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_EQ(rsFilterCacheManager->GetCacheState(), "No valid cache found.");
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    EXPECT_EQ(
        rsFilterCacheManager->GetCacheState(), "Snapshot found in cache. Generating filtered image using cached data.");
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    EXPECT_EQ(rsFilterCacheManager->GetCacheState(), "Filtered image found in cache. Reusing cached result.");
}

/**
 * @tc.name: UpdateCacheStateWithFilterHashTest
 * @tc.desc: test results of UpdateCacheStateWithFilterHash
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, UpdateCacheStateWithFilterHashTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    auto filter = std::make_shared<RSFilter>();
    rsFilterCacheManager->UpdateCacheStateWithFilterHash(filter);
    EXPECT_EQ(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->UpdateCacheStateWithFilterHash(filter);
    EXPECT_NE(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
    auto filterHash = filter->Hash();
    rsFilterCacheManager->UpdateCacheStateWithFilterHash(filter);
    EXPECT_EQ(rsFilterCacheManager->cachedFilterHash_, filterHash);
    rsFilterCacheManager->cachedFilterHash_ = 1;
    rsFilterCacheManager->UpdateCacheStateWithFilterHash(filter);
    EXPECT_NE(rsFilterCacheManager->cachedFilterHash_, filterHash);
}

/**
 * @tc.name: UpdateCacheStateWithFilterRegionTest
 * @tc.desc: test results of UpdateCacheStateWithFilterRegion
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, UpdateCacheStateWithFilterRegionTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    rsFilterCacheManager->UpdateCacheStateWithFilterRegion();
    EXPECT_FALSE(rsFilterCacheManager->IsCacheValid());
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    EXPECT_TRUE(rsFilterCacheManager->IsCacheValid());
    rsFilterCacheManager->UpdateCacheStateWithFilterRegion();
    EXPECT_FALSE(rsFilterCacheManager->IsCacheValid());
}

/**
 * @tc.name: UpdateCacheStateWithDirtyRegionTest001
 * @tc.desc: test results of UpdateCacheStateWithDirtyRegion
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, UpdateCacheStateWithDirtyRegionTest001, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    rsFilterCacheManager->UpdateCacheStateWithDirtyRegion();
    EXPECT_FALSE(rsFilterCacheManager->IsCacheValid());
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->cacheUpdateInterval_ = 1;
    rsFilterCacheManager->UpdateCacheStateWithDirtyRegion();
    EXPECT_TRUE(rsFilterCacheManager->pendingPurge_);
    rsFilterCacheManager->cacheUpdateInterval_ = -1;
    rsFilterCacheManager->UpdateCacheStateWithDirtyRegion();
    EXPECT_FALSE(rsFilterCacheManager->IsCacheValid());
}

/**
 * @tc.name: UpdateCacheStateWithDirtyRegionTest002
 * @tc.desc: test results of UpdateCacheStateWithDirtyRegion
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, UpdateCacheStateWithDirtyRegionTest002, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    RSDirtyRegionManager dirtyManager;
    EXPECT_FALSE(rsFilterCacheManager->UpdateCacheStateWithDirtyRegion(dirtyManager));
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    EXPECT_FALSE(rsFilterCacheManager->UpdateCacheStateWithDirtyRegion(dirtyManager));
    rsFilterCacheManager->pendingPurge_ = true;
    EXPECT_TRUE(rsFilterCacheManager->UpdateCacheStateWithDirtyRegion(dirtyManager));
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    // for test
    rsFilterCacheManager->snapshotRegion_.SetAll(5, 5, 10, 10);
    dirtyManager.currentFrameDirtyRegion_.SetAll(0, 0, 10, 10);
    rsFilterCacheManager->cacheUpdateInterval_ = 1;
    EXPECT_FALSE(rsFilterCacheManager->UpdateCacheStateWithDirtyRegion(dirtyManager));
    EXPECT_TRUE(rsFilterCacheManager->pendingPurge_);
    rsFilterCacheManager->cacheUpdateInterval_ = -1;
    EXPECT_FALSE(rsFilterCacheManager->UpdateCacheStateWithDirtyRegion(dirtyManager));
    EXPECT_FALSE(rsFilterCacheManager->IsCacheValid());
}

/**
 * @tc.name: DrawFilterWithoutSnapshotTest
 * @tc.desc: test results of DrawFilterWithoutSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, DrawFilterWithoutSnapshotTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    auto shaderFilter = std::make_shared<RSShaderFilter>();
    auto filter = std::make_shared<RSDrawingFilter>(shaderFilter);
    Drawing::RectI src;
    Drawing::RectI dst;
    EXPECT_FALSE(rsFilterCacheManager->DrawFilterWithoutSnapshot(filterCanvas, filter, src, dst, false));
}

/**
 * @tc.name: DrawFilterWithoutSnapshotTest002
 * @tc.desc: test results of DrawFilterWithoutSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIBE049
 */
HWTEST_F(RSFilterCacheManagerTest, DrawFilterWithoutSnapshotTest002, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    
    float blurRadius = 10.0f;
    auto kawaseBlurShaderFilter = std::make_shared<RSKawaseBlurShaderFilter>(blurRadius);
    auto drawingFilter = std::make_shared<RSDrawingFilter>(kawaseBlurShaderFilter);
    drawingFilter->SetFilterType(RSFilter::MATERIAL);

    Drawing::RectI srcRect{ 0, 0, 100, 100 };
    Drawing::RectI dstRect{ 0, 0, 100, 100 };
    int width = 100;
    int height = 100;
    Drawing::ImageInfo imageInfo{ width, height, Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
    std::shared_ptr<Drawing::Surface> surface = Drawing::Surface::MakeRaster(imageInfo);
    filterCanvas.surface_ = surface.get();
    EXPECT_NE(filterCanvas.GetSurface(), nullptr);
    rsFilterCacheManager->TakeSnapshot(filterCanvas, drawingFilter, srcRect);
    EXPECT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_NE(rsFilterCacheManager->cachedSnapshot_->cachedImage_, nullptr);
    EXPECT_TRUE(rsFilterCacheManager->DrawFilterWithoutSnapshot(filterCanvas, drawingFilter, srcRect, dstRect, true));
}

/**
 * @tc.name: DrawFilterTest
 * @tc.desc: test results of DrawFilter
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, DrawFilterTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    auto shaderFilter = std::make_shared<RSShaderFilter>();
    auto filter = std::make_shared<RSDrawingFilter>(shaderFilter);
    bool shouldClearFilteredCache = false;
    // for test
    std::optional<Drawing::RectI> srcRect(Drawing::RectI { 0, 0, 100, 100 });
    std::optional<Drawing::RectI> dstRect(Drawing::RectI { 0, 0, 100, 100 });
    rsFilterCacheManager->DrawFilter(filterCanvas, filter, true, shouldClearFilteredCache, srcRect, dstRect);
    EXPECT_TRUE(filterCanvas.GetDeviceClipBounds().IsEmpty());
}

/**
 * @tc.name: DrawFilterTest002
 * @tc.desc: test results of DrawFilter
 * @tc.type: FUNC
 * @tc.require: issueIBE049
 */
HWTEST_F(RSFilterCacheManagerTest, DrawFilterTest002, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    float blurRadius = 10.0f;
    auto kawaseBlurShaderFilter = std::make_shared<RSKawaseBlurShaderFilter>(blurRadius);
    auto drawingFilter = std::make_shared<RSDrawingFilter>(kawaseBlurShaderFilter);
    drawingFilter->SetFilterType(RSFilter::MATERIAL);
    std::optional<Drawing::RectI> srcRect(Drawing::RectI { 0, 0, 100, 100 });
    std::optional<Drawing::RectI> dstRect(Drawing::RectI { 0, 0, 100, 100 });
    int width = 100;
    int height = 100;
    Drawing::ImageInfo imageInfo{ width, height, Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
    std::shared_ptr<Drawing::Surface> surface = Drawing::Surface::MakeRaster(imageInfo);
    RSPaintFilterCanvas filterCanvas(surface.get());
    EXPECT_FALSE(filterCanvas.GetDeviceClipBounds().IsEmpty());
    bool shouldClearFilteredCache = false;
    rsFilterCacheManager->DrawFilter(filterCanvas, drawingFilter, true, shouldClearFilteredCache, srcRect, dstRect);
    EXPECT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_NE(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
    rsFilterCacheManager->renderClearFilteredCacheAfterDrawing_ = false;
    rsFilterCacheManager->CompactFilterCache();
    rsFilterCacheManager->renderClearFilteredCacheAfterDrawing_ = true;
    rsFilterCacheManager->CompactFilterCache();
    EXPECT_EQ(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_EQ(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
}

/**
 * @tc.name: GeneratedCachedEffectDataTest
 * @tc.desc: test results of GeneratedCachedEffectData
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, GeneratedCachedEffectDataTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    auto shaderFilter = std::make_shared<RSShaderFilter>();
    auto filter = std::make_shared<RSDrawingFilter>(shaderFilter);
    // for test
    std::optional<Drawing::RectI> srcRect(Drawing::RectI { 0, 0, 100, 100 });
    std::optional<Drawing::RectI> dstRect(Drawing::RectI { 0, 0, 100, 100 });
    rsFilterCacheManager->GeneratedCachedEffectData(filterCanvas, filter, srcRect, dstRect);
    EXPECT_TRUE(filterCanvas.GetDeviceClipBounds().IsEmpty());
}

/**
 * @tc.name: GeneratedCachedEffectDataTest002
 * @tc.desc: test results of GeneratedCachedEffectData
 * @tc.type: FUNC
 * @tc.require: issueIBE049
 */
HWTEST_F(RSFilterCacheManagerTest, GeneratedCachedEffectDataTest002, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    float blurRadius = 10.0f;
    auto kawaseBlurShaderFilter = std::make_shared<RSKawaseBlurShaderFilter>(blurRadius);
    auto drawingFilter = std::make_shared<RSDrawingFilter>(kawaseBlurShaderFilter);
    drawingFilter->SetFilterType(RSFilter::MATERIAL);
    std::optional<Drawing::RectI> srcRect(Drawing::RectI { 0, 0, 100, 100 });
    std::optional<Drawing::RectI> dstRect(Drawing::RectI { 0, 0, 100, 100 });
    int width = 100;
    int height = 100;
    Drawing::ImageInfo imageInfo{ width, height, Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
    std::shared_ptr<Drawing::Surface> surface = Drawing::Surface::MakeRaster(imageInfo);
    RSPaintFilterCanvas filterCanvas(surface.get());
    EXPECT_FALSE(filterCanvas.GetDeviceClipBounds().IsEmpty());
    const auto& [src, dst] = rsFilterCacheManager->ValidateParams(filterCanvas, srcRect, dstRect);
    EXPECT_FALSE(src.IsEmpty() || dst.IsEmpty());
    EXPECT_EQ(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_EQ(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
    auto cachedFilteredSnapshot =
        rsFilterCacheManager->GeneratedCachedEffectData(filterCanvas, drawingFilter, srcRect, dstRect);
    EXPECT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_NE(cachedFilteredSnapshot, nullptr);
}

/**
 * @tc.name: TakeSnapshotTest
 * @tc.desc: test results of TakeSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, TakeSnapshotTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    auto shaderFilter = std::make_shared<RSShaderFilter>();
    auto filter = std::make_shared<RSDrawingFilter>(shaderFilter);
    // for test
    Drawing::RectI srcRect(0, 0, 100, 100);
    rsFilterCacheManager->TakeSnapshot(filterCanvas, filter, srcRect);
    EXPECT_EQ(filterCanvas.GetSurface(), nullptr);
    filterCanvas.surface_ = new Drawing::Surface();
    rsFilterCacheManager->TakeSnapshot(filterCanvas, filter, srcRect);
    EXPECT_NE(filterCanvas.GetSurface(), nullptr);
    auto para = std::make_shared<RSMagnifierParams>();
    auto rsMagnifierShaderFilter = std::make_shared<RSMagnifierShaderFilter>(para);
    filter = std::make_shared<RSDrawingFilter>(rsMagnifierShaderFilter);
    rsFilterCacheManager->TakeSnapshot(filterCanvas, filter, srcRect);
    EXPECT_NE(filter->GetShaderFilterWithType(RSShaderFilter::MAGNIFIER), nullptr);
}

/**
 * @tc.name: TakeSnapshotTest002
 * @tc.desc: test results of TakeSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIBE049
 */
HWTEST_F(RSFilterCacheManagerTest, TakeSnapshotTest002, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    auto shaderFilter = std::make_shared<RSShaderFilter>();
    auto filter = std::make_shared<RSDrawingFilter>(shaderFilter);

    Drawing::RectI srcRect(0, 0, 100, 100);
    int width = 100;
    int height = 100;
    Drawing::ImageInfo imageInfo{ width, height, Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
    std::shared_ptr<Drawing::Surface> surface = Drawing::Surface::MakeRaster(imageInfo);
    filterCanvas.surface_ = surface.get();
    EXPECT_NE(filterCanvas.GetSurface(), nullptr);
    std::shared_ptr<Drawing::Image> snapShot = filterCanvas.GetSurface()->GetImageSnapshot(srcRect);
    EXPECT_NE(snapShot, nullptr);
    rsFilterCacheManager->TakeSnapshot(filterCanvas, filter, srcRect);
    EXPECT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
}

/**
 * @tc.name: GenerateFilteredSnapshotTest
 * @tc.desc: test results of GenerateFilteredSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, GenerateFilteredSnapshotTest, TestSize.Level1)
{
    auto manager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    std::shared_ptr<Drawing::ImageFilter> imageFilter = std::make_shared<Drawing::ImageFilter>();
    std::shared_ptr<RSDrawingFilter> filter = std::make_shared<RSDrawingFilter>(imageFilter, 0);
    Drawing::RectI dstRect;
    manager->GenerateFilteredSnapshot(canvas, filter, dstRect);
    EXPECT_TRUE(canvas.GetSurface() == nullptr);

    auto surfacePtr = std::make_shared<Drawing::Surface>();
    surfacePtr->impl_ = std::make_shared<Drawing::SkiaSurface>();
    canvas.surface_ = surfacePtr.get();
    manager->GenerateFilteredSnapshot(canvas, filter, dstRect);
    EXPECT_TRUE(canvas.GetSurface() != nullptr);
    EXPECT_TRUE(manager->cachedSnapshot_ == nullptr);

    manager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    manager->GenerateFilteredSnapshot(canvas, filter, dstRect);
    EXPECT_TRUE(manager->cachedSnapshot_ != nullptr);
    EXPECT_TRUE(manager->cachedSnapshot_->cachedImage_ == nullptr);

    manager->cachedSnapshot_->cachedImage_ = std::make_shared<Drawing::Image>();
    manager->GenerateFilteredSnapshot(canvas, filter, dstRect);
    EXPECT_TRUE(manager->cachedSnapshot_->cachedImage_ != nullptr);
}

/**
 * @tc.name: GenerateFilteredSnapshotTest002
 * @tc.desc: test results of GenerateFilteredSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIBE049
 */
HWTEST_F(RSFilterCacheManagerTest, GenerateFilteredSnapshotTest002, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    
    float blurRadius = 10.0f;
    auto kawaseBlurShaderFilter = std::make_shared<RSKawaseBlurShaderFilter>(blurRadius);
    auto drawingFilter = std::make_shared<RSDrawingFilter>(kawaseBlurShaderFilter);
    drawingFilter->SetFilterType(RSFilter::MATERIAL);

    Drawing::RectI srcRect{ 0, 0, 100, 100 };
    Drawing::RectI dstRect{ 0, 0, 100, 100 };
    int width = 100;
    int height = 100;
    Drawing::ImageInfo imageInfo{ width, height, Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
    std::shared_ptr<Drawing::Surface> surface = Drawing::Surface::MakeRaster(imageInfo);
    filterCanvas.surface_ = surface.get();
    EXPECT_NE(filterCanvas.GetSurface(), nullptr);
    auto offscreenSurface = filterCanvas.GetSurface()->MakeSurface(dstRect.GetWidth(), dstRect.GetHeight());
    EXPECT_NE(offscreenSurface, nullptr);
    rsFilterCacheManager->TakeSnapshot(filterCanvas, drawingFilter, srcRect);
    EXPECT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
    rsFilterCacheManager->GenerateFilteredSnapshot(filterCanvas, drawingFilter, dstRect);
    EXPECT_NE(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
}

/**
 * @tc.name: DrawCachedFilteredSnapshotTest
 * @tc.desc: test results of DrawCachedFilteredSnapshot
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, DrawCachedFilteredSnapshotTest, TestSize.Level1)
{
    auto manager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    auto shaderFilter = std::make_shared<RSShaderFilter>();
    auto filter = std::make_shared<RSDrawingFilter>(shaderFilter);
    std::shared_ptr<Drawing::ImageFilter> imageFilter = std::make_shared<Drawing::ImageFilter>();
    Drawing::RectI dstRect;
    manager->DrawCachedFilteredSnapshot(canvas, dstRect, filter);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ == nullptr);

    manager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    manager->DrawCachedFilteredSnapshot(canvas, dstRect, filter);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ != nullptr);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_->cachedImage_ == nullptr);

    manager->cachedFilteredSnapshot_->cachedImage_ = std::make_shared<Drawing::Image>();
    manager->DrawCachedFilteredSnapshot(canvas, dstRect, filter);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_->cachedImage_ != nullptr);

    canvas.visibleRect_.right_ = 10;
    canvas.visibleRect_.bottom_ = 10;
    manager->DrawCachedFilteredSnapshot(canvas, dstRect, filter);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_->cachedImage_ != nullptr);
}

/**
 * @tc.name: InvalidateFilterCacheTest
 * @tc.desc: test results of InvalidateFilterCache
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, InvalidateFilterCacheTest, TestSize.Level1)
{
    auto manager = std::make_shared<RSFilterCacheManager>();
    manager->InvalidateFilterCache(FilterCacheType::BOTH);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ == nullptr);

    manager->InvalidateFilterCache(FilterCacheType::SNAPSHOT);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ == nullptr);

    manager->InvalidateFilterCache(FilterCacheType::FILTERED_SNAPSHOT);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ == nullptr);
}

/**
 * @tc.name: SetAndGetFilterInvalidTest
 * @tc.desc: test results of SetAndGetFilterInvalid
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, SetAndGetFilterInvalidTest, TestSize.Level1)
{
    auto manager = std::make_shared<RSFilterCacheManager>();
    manager->SetFilterInvalid(true);
    EXPECT_TRUE(manager->GetFilterInvalid());

    manager->SetFilterInvalid(false);
    EXPECT_FALSE(manager->GetFilterInvalid());
}

/**
 * @tc.name: GetCachedTypeTest
 * @tc.desc: test results of GetCachedType
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, GetCachedTypeTest, TestSize.Level1)
{
    auto manager = std::make_shared<RSFilterCacheManager>();
    manager->GetCachedType();
    EXPECT_TRUE(manager->cachedSnapshot_ == nullptr);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ == nullptr);

    manager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    manager->GetCachedType();
    EXPECT_TRUE(manager->cachedSnapshot_ == nullptr);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_);

    manager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    manager->cachedFilteredSnapshot_ = nullptr;
    manager->GetCachedType();
    EXPECT_TRUE(manager->cachedSnapshot_);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_ == nullptr);

    manager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    manager->GetCachedType();
    EXPECT_TRUE(manager->cachedSnapshot_);
    EXPECT_TRUE(manager->cachedFilteredSnapshot_);
}

/**
 * @tc.name: CheckCachedImagesTest
 * @tc.desc: test results of CheckCachedImages
 * @tc.type:FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, CheckCachedImagesTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    rsFilterCacheManager->CheckCachedImages(filterCanvas);
    EXPECT_EQ(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_EQ(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);

    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->CheckCachedImages(filterCanvas);
    EXPECT_EQ(rsFilterCacheManager->cachedSnapshot_, nullptr);
    EXPECT_EQ(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
}

/**
 * @tc.name: ValidateParamsTest
 * @tc.desc: test results of ValidateParams
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, ValidateParamsTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    std::optional<Drawing::RectI> srcRect;
    std::optional<Drawing::RectI> dstRect;
    auto [src1, dst1] = rsFilterCacheManager->ValidateParams(filterCanvas, srcRect, dstRect);
    EXPECT_EQ(src1, filterCanvas.GetRoundInDeviceClipBounds());
    EXPECT_EQ(dst1, filterCanvas.GetRoundInDeviceClipBounds());
    // for test
    srcRect = Drawing::RectI { 0, 0, 100, 100 };
    dstRect = Drawing::RectI { 0, 0, 100, 100 };
    auto [src2, dst2] = rsFilterCacheManager->ValidateParams(filterCanvas, srcRect, dstRect);
    EXPECT_EQ(src2, srcRect);
    EXPECT_EQ(dst2, dstRect);
}

/**
 * @tc.name: CompactFilterCache
 * @tc.desc: test results of CompactFilterCache
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, CompactFilterCacheTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    rsFilterCacheManager->CompactFilterCache();
}

/**
 * @tc.name: SwapDataAndInitStagingFlags
 * @tc.desc: test results of SwapDataAndInitStagingFlags
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, SwapDataAndInitStagingFlagsTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_unique<RSFilterCacheManager>();
    auto rsStagingFilterCacheManager = std::make_unique<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    EXPECT_NE(rsStagingFilterCacheManager, nullptr);

    rsStagingFilterCacheManager->stagingFilterHashChanged_ = true;
    rsStagingFilterCacheManager->SwapDataAndInitStagingFlags(rsFilterCacheManager);
    EXPECT_FALSE(rsStagingFilterCacheManager->stagingFilterHashChanged_);
    rsFilterCacheManager.reset();
    rsStagingFilterCacheManager->SwapDataAndInitStagingFlags(rsFilterCacheManager);
}

/**
 * @tc.name: WouldDrawLargeAreaBlur
 * @tc.desc: test results of WouldDrawLargeAreaBlur
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, WouldDrawLargeAreaBlurTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    EXPECT_FALSE(rsFilterCacheManager->WouldDrawLargeAreaBlur());
    rsFilterCacheManager->stagingIsLargeArea_ = true;
    rsFilterCacheManager->canSkipFrame_ = false;
    EXPECT_TRUE(rsFilterCacheManager->WouldDrawLargeAreaBlur());
    rsFilterCacheManager->canSkipFrame_ = true;
    rsFilterCacheManager->cacheUpdateInterval_ = 1;
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    EXPECT_TRUE(rsFilterCacheManager->WouldDrawLargeAreaBlur());
    rsFilterCacheManager->cacheUpdateInterval_ = 0;
    EXPECT_FALSE(rsFilterCacheManager->WouldDrawLargeAreaBlur());
}

/**
 * @tc.name: WouldDrawLargeAreaBlurPrecisely
 * @tc.desc: test results of WouldDrawLargeAreaBlurPrecisely
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, WouldDrawLargeAreaBlurPrecisely, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    EXPECT_FALSE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
    rsFilterCacheManager->stagingIsLargeArea_ = true;
    rsFilterCacheManager->stagingForceClearCache_ = true;
    EXPECT_TRUE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
    rsFilterCacheManager->stagingForceClearCache_ = false;
    rsFilterCacheManager->canSkipFrame_ = false;
    rsFilterCacheManager->stagingFilterHashChanged_ = false;
    EXPECT_TRUE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
    rsFilterCacheManager->canSkipFrame_ = true;
    rsFilterCacheManager->stagingFilterRegionChanged_ = false;
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    EXPECT_FALSE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    rsFilterCacheManager->cacheUpdateInterval_ = 0;
    EXPECT_TRUE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
    rsFilterCacheManager->cacheUpdateInterval_ = 1;
    rsFilterCacheManager->stagingFilterHashChanged_ = true;
    rsFilterCacheManager->lastCacheType_ = FilterCacheType::FILTERED_SNAPSHOT;
    EXPECT_TRUE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
    rsFilterCacheManager->stagingFilterHashChanged_ = false;
    EXPECT_FALSE(rsFilterCacheManager->WouldDrawLargeAreaBlurPrecisely());
}

/**
 * @tc.name: IsFilterCacheValidForOcclusion
 * @tc.desc: test results of IsFilterCacheValidForOcclusion
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, IsFilterCacheValidForOcclusionTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    rsFilterCacheManager->IsFilterCacheValidForOcclusion();
    // cacheType: FilterCacheType::NONE
    rsFilterCacheManager->cachedSnapshot_ = nullptr;
    rsFilterCacheManager->cachedFilteredSnapshot_ = nullptr;
    EXPECT_FALSE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());

    // cacheType: FilterCacheType::SNAPSHOT
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    ASSERT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
    rsFilterCacheManager->cachedFilteredSnapshot_ = nullptr;
    EXPECT_TRUE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());
    rsFilterCacheManager->renderClearType_ = FilterCacheType::SNAPSHOT;
    rsFilterCacheManager->InvalidateFilterCache(rsFilterCacheManager->renderClearType_);
    EXPECT_FALSE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());

    // cacheType: FilterCacheType::BOTH
    rsFilterCacheManager->cachedSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    ASSERT_NE(rsFilterCacheManager->cachedSnapshot_, nullptr);
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    ASSERT_NE(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
    EXPECT_TRUE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());
    rsFilterCacheManager->renderClearType_ = FilterCacheType::BOTH;
    rsFilterCacheManager->InvalidateFilterCache(rsFilterCacheManager->renderClearType_);
    EXPECT_FALSE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());

    // cacheType: FilterCacheType::FILTERED_SNAPSHOT
    rsFilterCacheManager->cachedSnapshot_ = nullptr;
    rsFilterCacheManager->cachedFilteredSnapshot_ = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    ASSERT_NE(rsFilterCacheManager->cachedFilteredSnapshot_, nullptr);
    EXPECT_TRUE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());
    rsFilterCacheManager->renderClearType_ = FilterCacheType::FILTERED_SNAPSHOT;
    rsFilterCacheManager->InvalidateFilterCache(rsFilterCacheManager->renderClearType_);
    EXPECT_FALSE(rsFilterCacheManager->IsFilterCacheValidForOcclusion());
}

/**
 * @tc.name: IsForceUseFilterCache
 * @tc.desc: test results of IsForceUseFilterCache
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, IsForceUseFilterCacheTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);

    rsFilterCacheManager->MarkFilterForceUseCache(true);
    EXPECT_TRUE(rsFilterCacheManager->IsForceUseFilterCache());
    rsFilterCacheManager->MarkFilterForceUseCache(false);
    EXPECT_FALSE(rsFilterCacheManager->IsForceUseFilterCache());

    rsFilterCacheManager->MarkFilterForceClearCache();
    EXPECT_TRUE(rsFilterCacheManager->IsForceClearFilterCache());
    rsFilterCacheManager->stagingForceClearCache_ = false;
    EXPECT_FALSE(rsFilterCacheManager->IsForceClearFilterCache());

    rsFilterCacheManager->stagingFilterRegionChanged_ = false;
    rsFilterCacheManager->MarkFilterRegionChanged();
    EXPECT_TRUE(rsFilterCacheManager->stagingFilterRegionChanged_);

    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    rsFilterCacheManager->MarkFilterRegionInteractWithDirty();
    EXPECT_TRUE(rsFilterCacheManager->stagingFilterInteractWithDirty_);

    rsFilterCacheManager->stagingForceClearCacheForLastFrame_ = false;
    rsFilterCacheManager->MarkForceClearCacheWithLastFrame();
    EXPECT_TRUE(rsFilterCacheManager->stagingForceClearCacheForLastFrame_);

    rsFilterCacheManager->stagingIsLargeArea_ = false;
    rsFilterCacheManager->MarkFilterRegionIsLargeArea();
    EXPECT_TRUE(rsFilterCacheManager->stagingIsLargeArea_);

    rsFilterCacheManager->stagingIsEffectNode_ = false;
    rsFilterCacheManager->MarkEffectNode();
    EXPECT_TRUE(rsFilterCacheManager->stagingIsEffectNode_);

    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    rsFilterCacheManager->pendingPurge_ = true;
    EXPECT_TRUE(rsFilterCacheManager->NeedPendingPurge());
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    rsFilterCacheManager->pendingPurge_ = false;
    EXPECT_FALSE(rsFilterCacheManager->NeedPendingPurge());
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    rsFilterCacheManager->pendingPurge_ = true;
    EXPECT_FALSE(rsFilterCacheManager->NeedPendingPurge());

    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    rsFilterCacheManager->stagingRotationChanged_ = true;
    rsFilterCacheManager->cacheUpdateInterval_=1;
    EXPECT_TRUE(rsFilterCacheManager->IsSkippingFrame());
    rsFilterCacheManager->cacheUpdateInterval_=0;
    EXPECT_FALSE(rsFilterCacheManager->IsSkippingFrame());
    rsFilterCacheManager->cacheUpdateInterval_=1;
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    rsFilterCacheManager->stagingRotationChanged_ = false;
    EXPECT_FALSE(rsFilterCacheManager->IsSkippingFrame());
}

/**
 * @tc.name: MarkRotationChanged
 * @tc.desc: test results of MarkRotationChanged
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, MarkRotationChangedTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);

    rsFilterCacheManager->stagingRotationChanged_ = false;
    rsFilterCacheManager->MarkRotationChanged();
    EXPECT_TRUE(rsFilterCacheManager->stagingRotationChanged_);

    rsFilterCacheManager->stagingIsOccluded_ = false;
    rsFilterCacheManager->MarkNodeIsOccluded(true);
    EXPECT_TRUE(rsFilterCacheManager->stagingIsOccluded_);

    rsFilterCacheManager->isFilterCacheValid_ = true;
    EXPECT_TRUE(rsFilterCacheManager->IsFilterCacheValid());
    rsFilterCacheManager->isFilterCacheValid_ = false;
    EXPECT_FALSE(rsFilterCacheManager->IsFilterCacheValid());
}

/**
 * @tc.name: RecordFilterInfos
 * @tc.desc: test results of RecordFilterInfos
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, RecordFilterInfosTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    std::shared_ptr<RSDrawingFilter> rsFilter = nullptr;
    rsFilterCacheManager->RecordFilterInfos(rsFilter);
    std::shared_ptr<RSShaderFilter> shaderFilter = std::make_shared<RSShaderFilter>();
    EXPECT_NE(shaderFilter, nullptr);
    rsFilterCacheManager->stagingCachedFilterHash_ = 1;
    rsFilter = std::make_shared<RSDrawingFilter>(shaderFilter);
    rsFilterCacheManager->RecordFilterInfos(rsFilter);
    EXPECT_EQ(rsFilterCacheManager->stagingCachedFilterHash_, rsFilter->Hash());

    // RSProperties::FilterCacheEnabled is true
    rsFilterCacheManager->ClearFilterCache();
    rsFilterCacheManager->filterType_ = RSFilter::AIBAR;
    rsFilterCacheManager->stagingIsOccluded_ = true;
    rsFilterCacheManager->ClearFilterCache();
    rsFilterCacheManager->renderIsEffectNode_ = true;
    rsFilterCacheManager->ClearFilterCache();
    rsFilterCacheManager->stagingIsOccluded_ = false;
    rsFilterCacheManager->stagingFilterRegionChanged_ = true;
    rsFilterCacheManager->stagingClearType_ = FilterCacheType::FILTERED_SNAPSHOT;
    rsFilterCacheManager->cachedFilteredSnapshot_ =
    std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    rsFilterCacheManager->ClearFilterCache();

    rsFilterCacheManager->pendingPurge_ = true;
    rsFilterCacheManager->UpdateFlags(FilterCacheType::NONE, false);
    EXPECT_FALSE(rsFilterCacheManager->pendingPurge_);
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    rsFilterCacheManager->cacheUpdateInterval_ = 3;
    rsFilterCacheManager->UpdateFlags(FilterCacheType::NONE, true);
    EXPECT_EQ(rsFilterCacheManager->cacheUpdateInterval_, 2);
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    rsFilterCacheManager->stagingRotationChanged_ = true;
    rsFilterCacheManager->UpdateFlags(FilterCacheType::NONE, true);
    EXPECT_EQ(rsFilterCacheManager->cacheUpdateInterval_, 1);
    rsFilterCacheManager->stagingRotationChanged_ = false;
    rsFilterCacheManager->filterType_ = RSFilter::AIBAR;
    rsFilterCacheManager->UpdateFlags(FilterCacheType::NONE, true);
    EXPECT_EQ(rsFilterCacheManager->cacheUpdateInterval_, 1);
    rsFilterCacheManager->stagingIsAIBarInteractWithHWC_ = true;
    rsFilterCacheManager->cacheUpdateInterval_ = 0;
    rsFilterCacheManager->UpdateFlags(FilterCacheType::NONE, true);
    EXPECT_EQ(rsFilterCacheManager->cacheUpdateInterval_, 0);
    rsFilterCacheManager->cacheUpdateInterval_ = 3;
    rsFilterCacheManager->stagingIsAIBarInteractWithHWC_ = true;
    rsFilterCacheManager->UpdateFlags(FilterCacheType::NONE, true);
    EXPECT_EQ(rsFilterCacheManager->cacheUpdateInterval_, 2);
}

/**
 * @tc.name: IsAIBarCacheValid
 * @tc.desc: test results of IsAIBarCacheValid
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, IsAIBarCacheValidTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);

    EXPECT_FALSE(rsFilterCacheManager->IsAIBarCacheValid());
    rsFilterCacheManager->filterType_ = RSFilter::AIBAR;
    EXPECT_FALSE(rsFilterCacheManager->IsAIBarCacheValid());
    rsFilterCacheManager->cacheUpdateInterval_ = 1;
    rsFilterCacheManager->stagingForceClearCacheForLastFrame_ = true;
    EXPECT_FALSE(rsFilterCacheManager->IsAIBarCacheValid());
    rsFilterCacheManager->stagingForceClearCacheForLastFrame_ = false;
    EXPECT_TRUE(rsFilterCacheManager->IsAIBarCacheValid());
}

/**
 * @tc.name: MarkNeedClearFilterCache
 * @tc.desc: test results of MarkNeedClearFilterCache
 * @tc.type: FUNC
 * @tc.require: issueIA5FLZ
 */
HWTEST_F(RSFilterCacheManagerTest, MarkNeedClearFilterCacheTest, TestSize.Level1)
{
    auto rsFilterCacheManager = std::make_shared<RSFilterCacheManager>();
    EXPECT_NE(rsFilterCacheManager, nullptr);
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->isFilterCacheValid_ = true;
    rsFilterCacheManager->stagingForceClearCacheForLastFrame_ = true;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    EXPECT_FALSE(rsFilterCacheManager->isFilterCacheValid_);
    rsFilterCacheManager->stagingForceClearCacheForLastFrame_ = false;
    rsFilterCacheManager->lastCacheType_ = FilterCacheType::NONE;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->lastCacheType_ = FilterCacheType::SNAPSHOT;
    rsFilterCacheManager->stagingForceUseCache_ = true;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->stagingForceUseCache_ = false;
    rsFilterCacheManager->stagingForceClearCache_ = true;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->stagingForceClearCache_ = false;
    rsFilterCacheManager->stagingFilterRegionChanged_ = true;
    rsFilterCacheManager->stagingRotationChanged_ = false;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->stagingFilterRegionChanged_ = false;
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    rsFilterCacheManager->pendingPurge_ = true;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = true;
    rsFilterCacheManager->cacheUpdateInterval_ = 0;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->stagingFilterInteractWithDirty_ = false;
    rsFilterCacheManager->pendingPurge_ = false;
    rsFilterCacheManager->stagingRotationChanged_ = true;
    rsFilterCacheManager->cacheUpdateInterval_ = 0;
    rsFilterCacheManager->MarkNeedClearFilterCache();
    rsFilterCacheManager->cacheUpdateInterval_ = 1;
    rsFilterCacheManager->MarkNeedClearFilterCache();
}
} // namespace Rosen
} // namespace OHOS
