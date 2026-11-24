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
#include <string>
#include <unistd.h>

#include "effect_image_chain.h"
#include "effect_image_render.h"
#include "effect_tag_tracker.h"
#include "filter/filter.h"
#include "surface_buffer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class EffectTagTrackerUnittest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

namespace {
constexpr uint32_t TEST_CUSTOM_TAG_ID = 42;
constexpr uint32_t TEST_SCENE_TAG_ID = 11;
const char* TEST_SCENE_NAME = "chainScene";
const char* TEST_STATISTICS_TITLE = "EffectTagTracker GPU memory statistics";

std::shared_ptr<Media::PixelMap> CreateTestPixelMap(int32_t width = 1, int32_t height = 1)
{
    Media::InitializationOptions opts;
    opts.size = { width, height };
    opts.srcPixelFormat = Media::PixelFormat::RGBA_8888;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    return Media::PixelMap::Create(opts);
}

OH_NativeBuffer* CreateTestNativeBuffer(int32_t width, int32_t height)
{
    OH_NativeBuffer_Config config { .width = static_cast<uint32_t>(width),
        .height = static_cast<uint32_t>(height),
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA };
    return OH_NativeBuffer_Alloc(&config);
}

class SyncFenceFdGuard {
public:
    explicit SyncFenceFdGuard(int32_t* fd) : fd_(fd) {}
    ~SyncFenceFdGuard()
    {
        if (fd_ != nullptr && *fd_ >= 0) {
            close(*fd_);
            *fd_ = -1;
        }
    }
    SyncFenceFdGuard(const SyncFenceFdGuard&) = delete;
    SyncFenceFdGuard& operator=(const SyncFenceFdGuard&) = delete;

private:
    int32_t* fd_;
};
} // namespace

/**
 * @tc.name: EffectTagTrackerNullGpuContext001
 * @tc.desc: test EffectTagTracker constructed with null gpu context
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerNullGpuContext001, TestSize.Level1)
{
    EffectTagTracker tracker(nullptr);
    EXPECT_EQ(tracker.GetGpuContext(), nullptr);

    auto tag = tracker.GetTag();
    EXPECT_EQ(tag.fSid, EFFECT_MODULE_TAG);
    EXPECT_EQ(tag.fPid, static_cast<uint32_t>(getpid()));
    EXPECT_NE(tag.fTid, 0u);
    EXPECT_EQ(tag.fWid, 0u);
    EXPECT_EQ(tag.fFid, 0u);
    EXPECT_TRUE(tag.fName.empty());

    auto currentTag = tracker.GetCurrentGpuResourceTag();
    EXPECT_EQ(currentTag.fFid, 0u);
    EXPECT_TRUE(currentTag.fName.empty());

    tracker.SetTagEnd();

    std::string result = "untouched";
    EXPECT_FALSE(tracker.GetGpuMemoryStatistics(result));
}

/**
 * @tc.name: EffectTagTrackerWithGpuContext001
 * @tc.desc: test EffectTagTracker constructed with a valid gpu context
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerWithGpuContext001, TestSize.Level1)
{
    auto gpuContext = std::make_shared<Drawing::GPUContext>();
    ASSERT_NE(gpuContext, nullptr);
    EffectTagTracker tracker(gpuContext);
    EXPECT_EQ(tracker.GetGpuContext(), gpuContext);

    auto tag = tracker.GetTag();
    EXPECT_EQ(tag.fSid, EFFECT_MODULE_TAG);
    EXPECT_EQ(tag.fPid, static_cast<uint32_t>(getpid()));
    EXPECT_NE(tag.fTid, 0u);
    EXPECT_EQ(tag.fFid, 0u);

    auto nullTag = EffectTagTracker::GetCurrentGpuResourceTag(nullptr);
    EXPECT_EQ(nullTag.fFid, 0u);
    auto currentTag = EffectTagTracker::GetCurrentGpuResourceTag(gpuContext.get());
    EXPECT_EQ(currentTag.fFid, 0u);

    auto memberTag = tracker.GetCurrentGpuResourceTag();
    EXPECT_EQ(memberTag.fFid, 0u);

    std::string result;
    EXPECT_TRUE(tracker.GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find(TEST_STATISTICS_TITLE), std::string::npos);
}

/**
 * @tc.name: EffectTagTrackerCustomTag001
 * @tc.desc: test EffectTagTracker constructed with a custom tag
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerCustomTag001, TestSize.Level1)
{
    auto gpuContext = std::make_shared<Drawing::GPUContext>();
    EffectTagTracker tracker(gpuContext, TEST_CUSTOM_TAG_ID, "customScene");

    auto tag = tracker.GetTag();
    EXPECT_EQ(tag.fFid, TEST_CUSTOM_TAG_ID);
    EXPECT_EQ(tag.fName, "customScene");
    EXPECT_EQ(tag.fWid, 0u);
    EXPECT_EQ(tag.fSid, EFFECT_MODULE_TAG);

    std::string result;
    EXPECT_TRUE(tracker.GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find("customScene"), std::string::npos);
    EXPECT_NE(result.find("tagId=42"), std::string::npos);
}

/**
 * @tc.name: EffectTagTrackerCustomTagNullContext001
 * @tc.desc: test EffectTagTracker with a custom tag and null gpu context
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerCustomTagNullContext001, TestSize.Level1)
{
    EffectTagTracker tracker(nullptr, TEST_CUSTOM_TAG_ID, "nullContextScene");
    EXPECT_EQ(tracker.GetGpuContext(), nullptr);
    auto tag = tracker.GetTag();
    EXPECT_EQ(tag.fFid, TEST_CUSTOM_TAG_ID);
    EXPECT_EQ(tag.fName, "nullContextScene");

    tracker.SetTagEnd();

    std::string result;
    EXPECT_FALSE(tracker.GetGpuMemoryStatistics(result));
}

/**
 * @tc.name: EffectTagTrackerSetTagEnd001
 * @tc.desc: test SetTagEnd with a valid gpu context
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerSetTagEnd001, TestSize.Level1)
{
    auto gpuContext = std::make_shared<Drawing::GPUContext>();
    EffectTagTracker tracker(gpuContext);
    tracker.SetTagEnd();
    auto tag = tracker.GetTag();
    EXPECT_EQ(tag.fSid, EFFECT_MODULE_TAG);
    auto currentTag = tracker.GetCurrentGpuResourceTag();
    EXPECT_EQ(currentTag.fFid, 0u);
}

/**
 * @tc.name: EffectTagTrackerSetEnabled001
 * @tc.desc: test global enable/disable switch of the tracker
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerSetEnabled001, TestSize.Level1)
{
    EffectTagTracker::SetEnabled(false);
    {
        auto gpuContext = std::make_shared<Drawing::GPUContext>();
        EffectTagTracker tracker(gpuContext, TEST_CUSTOM_TAG_ID, "disabledScene");
        EXPECT_EQ(tracker.GetTag().fFid, TEST_CUSTOM_TAG_ID);
        EXPECT_EQ(tracker.GetTag().fName, "disabledScene");
        tracker.SetTagEnd();
    }
    {
        EffectTagTracker tracker(nullptr);
        tracker.SetTagEnd();
    }
    EffectTagTracker::SetEnabled(true);
    auto gpuContext = std::make_shared<Drawing::GPUContext>();
    EffectTagTracker tracker(gpuContext);
    std::string result;
    EXPECT_TRUE(tracker.GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find(TEST_STATISTICS_TITLE), std::string::npos);
}

/**
 * @tc.name: EffectTagTrackerDisabledCtor001
 * @tc.desc: test single-arg constructor with a valid gpu context while the tracker is disabled
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerDisabledCtor001, TestSize.Level1)
{
    EffectTagTracker::SetEnabled(false);
    auto gpuContext = std::make_shared<Drawing::GPUContext>();
    EffectTagTracker tracker(gpuContext);
    EXPECT_EQ(tracker.GetGpuContext(), gpuContext);
    EXPECT_EQ(tracker.GetTag().fSid, EFFECT_MODULE_TAG);
    std::string result;
    EXPECT_TRUE(tracker.GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find(TEST_STATISTICS_TITLE), std::string::npos);
    EffectTagTracker::SetEnabled(true);
}

/**
 * @tc.name: EffectTagTrackerDumpMemoryStatistics001
 * @tc.desc: test dump utility with null and valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectTagTrackerDumpMemoryStatistics001, TestSize.Level1)
{
    auto gpuContext = std::make_shared<Drawing::GPUContext>();
    ASSERT_NE(gpuContext, nullptr);
    Drawing::GPUResourceTag tag(1, 2, 0, 3, "dumpTag");
    Drawing::TraceMemoryDump dump("category", true);

    EffectTagTracker::DumpMemoryStatisticsByTag(nullptr, &dump, tag);
    EffectTagTracker::DumpMemoryStatisticsByTag(gpuContext.get(), nullptr, tag);
    EffectTagTracker::DumpMemoryStatisticsByTag(gpuContext.get(), &dump, tag);

    EffectTagTracker nullTracker(nullptr);
    EXPECT_EQ(nullTracker.GetGpuContext(), nullptr);
    EXPECT_EQ(nullTracker.GetTag().fSid, EFFECT_MODULE_TAG);
    nullTracker.DumpMemoryStatisticsByTag(&dump, tag);
    EffectTagTracker tracker(gpuContext, 8, "memberScene");
    EXPECT_EQ(tracker.GetGpuContext(), gpuContext);
    EXPECT_EQ(tracker.GetTag().fFid, 8u);
    EXPECT_EQ(tracker.GetTag().fName, "memberScene");
    tracker.DumpMemoryStatisticsByTag(nullptr, tag);
    tracker.DumpMemoryStatisticsByTag(&dump, tag);
    EXPECT_EQ(tracker.GetTag().fSid, EFFECT_MODULE_TAG);
    EXPECT_EQ(tracker.GetTag().fFid, 8u);
    EXPECT_EQ(tracker.GetTag().fName, "memberScene");
}

/**
 * @tc.name: EffectImageChainGpuResourceTag001
 * @tc.desc: test EffectImageChain custom gpu resource tag and statistics
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectImageChainGpuResourceTag001, TestSize.Level1)
{
    auto image = std::make_shared<EffectImageChain>();
    ASSERT_NE(image, nullptr);

    EXPECT_EQ(image->GetEffectTagTracker(), nullptr);
    std::string result;
    EXPECT_FALSE(image->GetGpuMemoryStatistics(result));

    image->SetGpuResourceTag(TEST_SCENE_TAG_ID, TEST_SCENE_NAME);
    EXPECT_EQ(image->customTagId_, TEST_SCENE_TAG_ID);
    EXPECT_EQ(image->customTagName_, TEST_SCENE_NAME);

    auto srcPixelMap = CreateTestPixelMap();
    ASSERT_NE(srcPixelMap, nullptr);
    auto ret = image->Prepare(srcPixelMap, false);
    ASSERT_EQ(ret, DrawingError::ERR_OK);

    auto* tracker = image->GetEffectTagTracker();
    ASSERT_NE(tracker, nullptr);
    EXPECT_EQ(tracker->GetTag().fFid, TEST_SCENE_TAG_ID);
    EXPECT_EQ(tracker->GetTag().fName, TEST_SCENE_NAME);

    EXPECT_TRUE(image->GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find(TEST_SCENE_NAME), std::string::npos);
}

/**
 * @tc.name: EffectImageChainDefaultTag001
 * @tc.desc: test EffectImageChain default tracker when no custom tag is set
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectImageChainDefaultTag001, TestSize.Level1)
{
    auto image = std::make_shared<EffectImageChain>();
    ASSERT_NE(image, nullptr);
    auto srcPixelMap = CreateTestPixelMap();
    ASSERT_NE(srcPixelMap, nullptr);

    auto ret = image->Prepare(srcPixelMap, false);
    ASSERT_EQ(ret, DrawingError::ERR_OK);
    auto* tracker = image->GetEffectTagTracker();
    ASSERT_NE(tracker, nullptr);
    EXPECT_EQ(tracker->GetTag().fFid, 0u);
    EXPECT_TRUE(tracker->GetTag().fName.empty());
    EXPECT_EQ(tracker->GetTag().fSid, EFFECT_MODULE_TAG);

    std::string result;
    EXPECT_TRUE(image->GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find(TEST_STATISTICS_TITLE), std::string::npos);
}

/**
 * @tc.name: EffectImageChainNativeBufferTag001
 * @tc.desc: test EffectImageChain tracker on the native buffer prepare path
 * @tc.type: FUNC
 */
#if defined(RS_ENABLE_VK) && !defined(ROSEN_ARKUI_X)
HWTEST_F(EffectTagTrackerUnittest, EffectImageChainNativeBufferTag001, TestSize.Level1)
{
    const int32_t width = 4;
    const int32_t height = 4;
    auto srcPixelMap = CreateTestPixelMap(width, height);
    ASSERT_NE(srcPixelMap, nullptr);
    OH_NativeBuffer* dstBuffer = CreateTestNativeBuffer(width, height);
    ASSERT_NE(dstBuffer, nullptr);
    std::shared_ptr<OH_NativeBuffer> dst(dstBuffer, [](OH_NativeBuffer* buffer) {});

    auto image = std::make_shared<EffectImageChain>();
    image->SetGpuResourceTag(21, "bufferScene");
    auto ret = image->PrepareNativeBuffer(srcPixelMap, dst);
    ASSERT_EQ(ret, DrawingError::ERR_OK);

    auto* tracker = image->GetEffectTagTracker();
    ASSERT_NE(tracker, nullptr);
    EXPECT_EQ(tracker->GetTag().fFid, 21u);
    EXPECT_EQ(tracker->GetTag().fName, "bufferScene");

    std::string result;
    EXPECT_TRUE(image->GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find("bufferScene"), std::string::npos);

    OH_NativeBuffer_Unreference(dstBuffer);
}
#endif

/**
 * @tc.name: EffectImageChainRetagPrepare001
 * @tc.desc: test same chain consecutive GPU prepares with different tags keep context tag in sync
 * @tc.type: FUNC
 */
#if defined(RS_ENABLE_VK) && !defined(ROSEN_ARKUI_X)
HWTEST_F(EffectTagTrackerUnittest, EffectImageChainRetagPrepare001, TestSize.Level1)
{
    const int32_t width = 4;
    const int32_t height = 4;
    auto srcPixelMap = CreateTestPixelMap(width, height);
    ASSERT_NE(srcPixelMap, nullptr);
    OH_NativeBuffer* dstBuffer = CreateTestNativeBuffer(width, height);
    ASSERT_NE(dstBuffer, nullptr);
    std::shared_ptr<OH_NativeBuffer> dst(dstBuffer, [](OH_NativeBuffer* buffer) {});

    auto image = std::make_shared<EffectImageChain>();
    image->SetGpuResourceTag(11, "firstScene");
    ASSERT_EQ(image->PrepareNativeBuffer(srcPixelMap, dst), DrawingError::ERR_OK);
    auto* tracker = image->GetEffectTagTracker();
    ASSERT_NE(tracker, nullptr);
    EXPECT_EQ(tracker->GetTag().fFid, 11u);

    image->SetGpuResourceTag(22, "secondScene");
    ASSERT_EQ(image->PrepareNativeBuffer(srcPixelMap, dst), DrawingError::ERR_OK);
    tracker = image->GetEffectTagTracker();
    ASSERT_NE(tracker, nullptr);
    EXPECT_EQ(tracker->GetTag().fFid, 22u);
    EXPECT_EQ(tracker->GetCurrentGpuResourceTag().fFid, 22u);

    std::string result;
    EXPECT_TRUE(image->GetGpuMemoryStatistics(result));
    EXPECT_NE(result.find("secondScene"), std::string::npos);

    OH_NativeBuffer_Unreference(dstBuffer);
}
#endif

/**
 * @tc.name: EffectImageRenderGpuStatistics001
 * @tc.desc: test EffectImageRender::Render collecting gpu memory statistics
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, EffectImageRenderGpuStatistics001, TestSize.Level1)
{
    const int32_t width = 4;
    const int32_t height = 4;
    auto srcPixelMap = CreateTestPixelMap(width, height);
    ASSERT_NE(srcPixelMap, nullptr);
    std::vector<std::shared_ptr<EffectImageFilter>> imageFilters;
    imageFilters.emplace_back(EffectImageFilter::Blur(0.5));
    ASSERT_NE(imageFilters.front(), nullptr);

    std::shared_ptr<Media::PixelMap> dstPixelMap = nullptr;
    std::string statistics;
    EffectImageRender imageRender;

    auto ret = imageRender.Render(
        srcPixelMap, imageFilters, true, dstPixelMap, 31, "cpuScene", &statistics);
    ASSERT_EQ(ret, DrawingError::ERR_OK);
    EXPECT_EQ(statistics.find(TEST_STATISTICS_TITLE), std::string::npos);

    ret = imageRender.Render(
        srcPixelMap, imageFilters, false, dstPixelMap, 32, "gpuScene", &statistics);
    ASSERT_EQ(ret, DrawingError::ERR_OK);
    EXPECT_NE(statistics.find("gpuScene"), std::string::npos);
    EXPECT_NE(statistics.find(TEST_STATISTICS_TITLE), std::string::npos);
}

/**
 * @tc.name: EffectImageRenderNativeBufferStatistics001
 * @tc.desc: test EffectImageRender::RenderNativeBuffer collecting gpu memory statistics
 * @tc.type: FUNC
 */
#if defined(RS_ENABLE_VK) && !defined(ROSEN_ARKUI_X)
HWTEST_F(EffectTagTrackerUnittest, EffectImageRenderNativeBufferStatistics001, TestSize.Level1)
{
    const int32_t width = 4;
    const int32_t height = 4;
    auto srcPixelMap = CreateTestPixelMap(width, height);
    ASSERT_NE(srcPixelMap, nullptr);
    OH_NativeBuffer* dstBuffer = CreateTestNativeBuffer(width, height);
    ASSERT_NE(dstBuffer, nullptr);
    std::shared_ptr<OH_NativeBuffer> dst(dstBuffer, [](OH_NativeBuffer* buffer) {});
    std::vector<std::shared_ptr<EffectImageFilter>> imageFilters;
    imageFilters.emplace_back(EffectImageFilter::Blur(0.5));

    int32_t syncFenceFd = -1;
    SyncFenceFdGuard syncFenceFdGuard(&syncFenceFd);
    std::string statistics;
    EffectImageRender imageRender;
    auto ret = imageRender.RenderNativeBuffer(
        srcPixelMap, dst, imageFilters, &syncFenceFd, true, 33, "nativeScene", &statistics);
    ASSERT_EQ(ret, DrawingError::ERR_OK);
    EXPECT_NE(statistics.find("nativeScene"), std::string::npos);
    EXPECT_NE(statistics.find(TEST_STATISTICS_TITLE), std::string::npos);

    OH_NativeBuffer_Unreference(dstBuffer);
}
#endif

/**
 * @tc.name: FilterSetGpuResourceTag001
 * @tc.desc: test Filter::SetGpuResourceTag with tag name truncation
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, FilterSetGpuResourceTag001, TestSize.Level1)
{
    auto srcPixelMap = CreateTestPixelMap();
    ASSERT_NE(srcPixelMap, nullptr);
    Filter filter(srcPixelMap);

    EXPECT_TRUE(filter.GetGpuMemoryStatistics().empty());
    EXPECT_TRUE(filter.GetDefaultTagName().empty());

    std::string longName(100, 'a');
    filter.SetGpuResourceTag(5, longName);
    EXPECT_EQ(filter.customTagId_, 5u);
    EXPECT_EQ(filter.customTagName_.size(), 64u);
    EXPECT_EQ(filter.customTagName_, longName.substr(0, 64));

    filter.SetGpuResourceTag(6, "filterScene");
    EXPECT_EQ(filter.customTagId_, 6u);
    EXPECT_EQ(filter.customTagName_, "filterScene");
}

/**
 * @tc.name: FilterDefaultTagNameDedup001
 * @tc.desc: test Filter default tag name built from deduplicated filter types
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, FilterDefaultTagNameDedup001, TestSize.Level1)
{
    auto srcPixelMap = CreateTestPixelMap();
    ASSERT_NE(srcPixelMap, nullptr);
    Filter filter(srcPixelMap);

    EXPECT_TRUE(filter.Blur(1.0f));
    EXPECT_TRUE(filter.Blur(2.0f));
    EXPECT_TRUE(filter.Brightness(0.5f));
    EXPECT_EQ(filter.GetDefaultTagName(), "blur+brightness");
    EXPECT_EQ(filter.filterTypeNames_.size(), 2u);

    filter.SetGpuResourceTag(9, "filterScene");
    auto dstPixelMap = filter.GetPixelMap(true);
    EXPECT_NE(dstPixelMap, nullptr);
    EXPECT_TRUE(filter.GetGpuMemoryStatistics().empty());
}

/**
 * @tc.name: FilterNullInputRender001
 * @tc.desc: test Filter render entry points with null source pixelmap and null dst buffer
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, FilterNullInputRender001, TestSize.Level1)
{
    Filter emptyFilter;
    EXPECT_EQ(emptyFilter.GetPixelMap(true), nullptr);

    int32_t syncFenceFd = -1;
    EXPECT_FALSE(emptyFilter.RenderNativeBuffer(false, nullptr, &syncFenceFd, false));

    const int32_t width = 4;
    const int32_t height = 4;
    OH_NativeBuffer* dstBuffer = CreateTestNativeBuffer(width, height);
    ASSERT_NE(dstBuffer, nullptr);
    EXPECT_FALSE(emptyFilter.RenderNativeBuffer(false, dstBuffer, &syncFenceFd, false));
    OH_NativeBuffer_Unreference(dstBuffer);
}

/**
 * @tc.name: FilterGpuThenCpuStats001
 * @tc.desc: test GPU then CPU render publishes per-round statistics without stale data
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, FilterGpuThenCpuStats001, TestSize.Level1)
{
    auto srcPixelMap = CreateTestPixelMap();
    ASSERT_NE(srcPixelMap, nullptr);
    Filter filter(srcPixelMap);
    EXPECT_TRUE(filter.Blur(1.0f));
    filter.SetGpuResourceTag(7, "gpuCpuOrder");

    EXPECT_NE(filter.GetPixelMap(false), nullptr);

    std::string gpuStats = filter.GetGpuMemoryStatistics();
    EXPECT_NE(gpuStats.find("gpuCpuOrder"), std::string::npos);

    auto dstPixelMap = filter.GetPixelMap(true);
    EXPECT_NE(dstPixelMap, nullptr);
    EXPECT_TRUE(filter.GetGpuMemoryStatistics().empty());
}

/**
 * @tc.name: FilterEmptyTagNameFallback001
 * @tc.desc: test empty tag name falls back to the default filter-type name with the id kept
 * @tc.type: FUNC
 */
HWTEST_F(EffectTagTrackerUnittest, FilterEmptyTagNameFallback001, TestSize.Level1)
{
    auto srcPixelMap = CreateTestPixelMap();
    ASSERT_NE(srcPixelMap, nullptr);
    Filter filter(srcPixelMap);
    EXPECT_TRUE(filter.Blur(1.0f));
    filter.SetGpuResourceTag(42, "");

    EXPECT_NE(filter.GetPixelMap(false), nullptr);

    std::string stats = filter.GetGpuMemoryStatistics();
    EXPECT_NE(stats.find("tagId=42"), std::string::npos);
    EXPECT_NE(stats.find("tagName=blur"), std::string::npos);
}

} // namespace Rosen
} // namespace OHOS