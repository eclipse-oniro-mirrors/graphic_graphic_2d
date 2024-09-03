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

#include "render/rs_image_cache.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSImageCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSImageCacheTest::SetUpTestCase() {}
void RSImageCacheTest::TearDownTestCase() {}
void RSImageCacheTest::SetUp() {}
void RSImageCacheTest::TearDown() {}

/**
 * @tc.name: InstanceTest
 * @tc.desc: Verify function Instance
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, InstanceTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    EXPECT_TRUE(imageCache.pixelMapCache_.empty());
}

/**
 * @tc.name: CacheDrawingImageTest
 * @tc.desc: Verify function CacheDrawingImage
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, CacheDrawingImageTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    EXPECT_FALSE(imageCache.drawingImageCache_.empty());
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: GetDrawingImageCacheTest
 * @tc.desc: Verify function GetDrawingImageCache
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, GetDrawingImageCacheTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    EXPECT_EQ(imageCache.GetDrawingImageCache(0), nullptr);
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    EXPECT_EQ(imageCache.GetDrawingImageCache(0), nullptr);
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: IncreaseDrawingImageCacheRefCountTest
 * @tc.desc: Verify function IncreaseDrawingImageCacheRefCount
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, IncreaseDrawingImageCacheRefCountTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    imageCache.IncreaseDrawingImageCacheRefCount(0);
    EXPECT_FALSE(imageCache.drawingImageCache_.empty());
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: ReleaseDrawingImageCacheTest
 * @tc.desc: Verify function ReleaseDrawingImageCache
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, ReleaseDrawingImageCacheTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    imageCache.ReleaseDrawingImageCache(0);
    EXPECT_FALSE(imageCache.drawingImageCache_.empty());
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: GetPixelMapCacheTest
 * @tc.desc: Verify function GetPixelMapCache
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, GetPixelMapCacheTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    EXPECT_EQ(imageCache.GetPixelMapCache(0), nullptr);
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    EXPECT_EQ(imageCache.GetPixelMapCache(0), nullptr);
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: IncreasePixelMapCacheRefCountTest
 * @tc.desc: Verify function IncreasePixelMapCacheRefCount
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, IncreasePixelMapCacheRefCountTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    imageCache.IncreasePixelMapCacheRefCount(0);
    EXPECT_FALSE(imageCache.drawingImageCache_.empty());
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: ReleasePixelMapCacheTest
 * @tc.desc: Verify function ReleasePixelMapCache
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, ReleasePixelMapCacheTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    imageCache.ReleasePixelMapCache(0);
    EXPECT_TRUE(true);
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheDrawingImage(1, img);
    imageCache.ReleasePixelMapCache(0);
    EXPECT_FALSE(imageCache.drawingImageCache_.empty());
    imageCache.drawingImageCache_.clear();
}

/**
 * @tc.name: CacheRenderDrawingImageByPixelMapIdTest
 * @tc.desc: Verify function CacheRenderDrawingImageByPixelMapId
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, CacheRenderDrawingImageByPixelMapIdTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheRenderDrawingImageByPixelMapId(1, img, 0);
    EXPECT_FALSE(imageCache.pixelMapIdRelatedDrawingImageCache_.empty());
    imageCache.pixelMapIdRelatedDrawingImageCache_.clear();
}

/**
 * @tc.name: GetRenderDrawingImageCacheByPixelMapIdTest
 * @tc.desc: Verify function GetRenderDrawingImageCacheByPixelMapId
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, GetRenderDrawingImageCacheByPixelMapIdTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    EXPECT_EQ(imageCache.GetRenderDrawingImageCacheByPixelMapId(0, 0), nullptr);
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheRenderDrawingImageByPixelMapId(1, img, 0);
    EXPECT_EQ(imageCache.GetRenderDrawingImageCacheByPixelMapId(0, 0), nullptr);
    imageCache.pixelMapIdRelatedDrawingImageCache_.clear();
}

/**
 * @tc.name: ReleaseDrawingImageCacheByPixelMapIdTest
 * @tc.desc: Verify function ReleaseDrawingImageCacheByPixelMapId
 * @tc.type:FUNC
 * @tc.require: issueI9I9D1
 */
HWTEST_F(RSImageCacheTest, ReleaseDrawingImageCacheByPixelMapIdTest, TestSize.Level1)
{
    RSImageCache& imageCache = RSImageCache::Instance();
    auto img = std::make_shared<Drawing::Image>();
    imageCache.CacheRenderDrawingImageByPixelMapId(1, img, 0);
    imageCache.ReleaseDrawingImageCacheByPixelMapId(0);
    EXPECT_FALSE(imageCache.pixelMapIdRelatedDrawingImageCache_.empty());
    imageCache.pixelMapIdRelatedDrawingImageCache_.clear();
}
} // namespace OHOS::Rosen