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

#include "info_collection/rs_gpu_dirty_region_collection.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class GpuDirtyRegionCollectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void GpuDirtyRegionCollectionTest::SetUpTestCase() {}
void GpuDirtyRegionCollectionTest::TearDownTestCase() {}
void GpuDirtyRegionCollectionTest::SetUp() {}
void GpuDirtyRegionCollectionTest::TearDown() {}

/**
 * @tc.name: UpdateActiveDirtyInfoForDFXTest001
 * @tc.desc: UpdateActiveDirtyInfoForDFX test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, UpdateActiveDirtyInfoForDFXTest001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    std::string windowName = "TestWindow";
    NodeId id = 1;
    std::vector<RectI> rectIs;
    EXPECT_TRUE(rectIs.empty());
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rectIs);
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_[id].activeFramesNumber == 0);

    RectI rect = { 1, 1, 1, 1 };
    rectIs.emplace_back(rect);
    EXPECT_FALSE(rectIs.empty());
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rectIs);
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_[id].activeFramesNumber > 0);
}

/**
 * @tc.name: UpdateActiveDirtyInfoForDFXTest002
 * @tc.desc: UpdateActiveDirtyInfoForDFX test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, UpdateActiveDirtyInfoForDFXTest002, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    std::string windowName = "TestWindow";
    NodeId id = 1;
    Rect rect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rect);
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_[id].activeFramesNumber > 0);
}

/**
 * @tc.name: UpdateActiveDirtyInfoForDFXTest003
 * @tc.desc: Test UpdateActiveDirtyInfoForDFX with vector<RectI> when map reaches max capacity (10000)
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(GpuDirtyRegionCollectionTest, UpdateActiveDirtyInfoForDFXTest003, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    ASSERT_NE(gpuDirtyRegionCollection, nullptr);

    // Fill the map to reach MAX_SIZE (10000) + 1
    constexpr uint32_t MAX_SIZE = 10000;
    std::string windowName = "TestWindow";
    NodeId baseId = 1;

    // Add entries until map size equals MAX_SIZE
    for (uint32_t i = 0; i < MAX_SIZE; i++) {
        NodeId id = baseId + i;
        RectI rect = { 1, 1, 1, 1 };
        std::vector<RectI> rectIs = { rect };
        gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rectIs);
    }

    // Verify map size reached MAX_SIZE
    EXPECT_EQ(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.size(), MAX_SIZE);

    // Try to add one more entry - should be rejected due to capacity limit
    NodeId newId = baseId + MAX_SIZE;
    RectI newRect = { 1, 1, 1, 1 };
    std::vector<RectI> newRectIs = { newRect };
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(newId, windowName, newRectIs);

    // Map size should remain at MAX_SIZE (new entry rejected)
    EXPECT_EQ(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.size(), MAX_SIZE);

    // Verify original entries are still accessible
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_[baseId].activeFramesNumber > 0);

    // Reset for other tests
    gpuDirtyRegionCollection->ResetActiveDirtyRegionInfo();
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.empty());
}

/**
 * @tc.name: UpdateActiveDirtyInfoForDFXTest004
 * @tc.desc: Test UpdateActiveDirtyInfoForDFX with Rect when map reaches max capacity (10000)
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(GpuDirtyRegionCollectionTest, UpdateActiveDirtyInfoForDFXTest004, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    ASSERT_NE(gpuDirtyRegionCollection, nullptr);

    // Fill the map to reach MAX_SIZE (10000) + 1
    constexpr uint32_t MAX_SIZE = 10000;
    std::string windowName = "TestWindow";
    NodeId baseId = 1;

    // Add entries until map size equals MAX_SIZE
    for (uint32_t i = 0; i < MAX_SIZE; i++) {
        NodeId id = baseId + i;
        Rect rect = { 1, 1, 1, 1 };
        gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rect);
    }

    // Verify map size reached MAX_SIZE
    EXPECT_EQ(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.size(), MAX_SIZE);

    // Try to add one more entry - should be rejected due to capacity limit
    NodeId newId = baseId + MAX_SIZE;
    Rect newRect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(newId, windowName, newRect);

    // Map size should remain at MAX_SIZE (new entry rejected)
    EXPECT_EQ(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.size(), MAX_SIZE);

    // Verify original entries are still accessible
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_[baseId].activeFramesNumber > 0);

    // Reset for other tests
    gpuDirtyRegionCollection->ResetActiveDirtyRegionInfo();
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.empty());
}

/**
 * @tc.name: UpdateGlobalDirtyInfoForDFX001
 * @tc.desc: UpdateGlobalDirtyInfoForDFX test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, UpdateGlobalDirtyInfoForDFX001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    std::string windowName = "TestWindow";
    RectI rect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateGlobalDirtyInfoForDFX(rect);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.globalFramesNumber > 0);
}

/**
 * @tc.name: AddSkipProcessFramesNumberForDFX001
 * @tc.desc: AddSkipProcessFramesNumberForDFX test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, AddSkipProcessFramesNumberForDFX001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipProcessFramesNumber == 0);

    pid_t pid = 1;
    gpuDirtyRegionCollection->AddSkipProcessFramesNumberForDFX(pid);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipProcessFramesNumber > 0);
}

/**
 * @tc.name: GetActiveDirtyRegionInfo001
 * @tc.desc: GetActiveDirtyRegionInfo test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, GetActiveDirtyRegionInfo001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    auto res1 = gpuDirtyRegionCollection->GetActiveDirtyRegionInfo();
    EXPECT_TRUE(res1.size() == 0);

    std::string windowName = "TestWindow";
    NodeId id = 1;
    Rect rect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rect);

    auto res2 = gpuDirtyRegionCollection->GetActiveDirtyRegionInfo();
    EXPECT_FALSE(res1.size() == 1);
}

/**
 * @tc.name: GetGlobalDirtyRegionInfo001
 * @tc.desc: GetGlobalDirtyRegionInfo test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, GetGlobalDirtyRegionInfo001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    auto res1 = gpuDirtyRegionCollection->GetGlobalDirtyRegionInfo();
    EXPECT_TRUE(res1.globalFramesNumber == 0);

    std::string windowName = "TestWindow";
    RectI rect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateGlobalDirtyInfoForDFX(rect);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.globalFramesNumber > 0);

    auto res2 = gpuDirtyRegionCollection->GetGlobalDirtyRegionInfo();
    EXPECT_TRUE(res2.globalFramesNumber > 0);
}

/**
 * @tc.name: ResetActiveDirtyRegionInfo001
 * @tc.desc: ResetActiveDirtyRegionInfo test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, ResetActiveDirtyRegionInfo001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    std::string windowName = "TestWindow";
    NodeId id = 1;
    Rect rect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateActiveDirtyInfoForDFX(id, windowName, rect);

    auto res2 = gpuDirtyRegionCollection->GetActiveDirtyRegionInfo();
    EXPECT_FALSE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.empty());

    gpuDirtyRegionCollection->ResetActiveDirtyRegionInfo();
    EXPECT_TRUE(gpuDirtyRegionCollection->activeDirtyRegionInfoMap_.empty());
}

/**
 * @tc.name: ResetGlobalDirtyRegionInfo001
 * @tc.desc: ResetGlobalDirtyRegionInfo test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, ResetGlobalDirtyRegionInfo001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);

    std::string windowName = "TestWindow";
    RectI rect = { 1, 1, 1, 1 };
    gpuDirtyRegionCollection->UpdateGlobalDirtyInfoForDFX(rect);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.globalFramesNumber > 0);

    gpuDirtyRegionCollection->ResetGlobalDirtyRegionInfo();
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.globalFramesNumber == 0);
}

/**
 * @tc.name: GetMostSendingPidWhenDisplayNodeSkip001
 * @tc.desc: GetMostSendingPidWhenDisplayNodeSkip test
 * @tc.type:FUNC
 * @tc.require: issueI9VSPU
 */
HWTEST_F(GpuDirtyRegionCollectionTest, GetMostSendingPidWhenDisplayNodeSkip001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    EXPECT_NE(gpuDirtyRegionCollection, nullptr);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipProcessFramesNumber == 0);

    auto res1 = gpuDirtyRegionCollection->GetMostSendingPidWhenDisplayNodeSkip();
    EXPECT_TRUE(res1 == 0);

    pid_t pid = 1;
    gpuDirtyRegionCollection->AddSkipProcessFramesNumberForDFX(pid);
    EXPECT_TRUE(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipProcessFramesNumber > 0);
    auto res2 = gpuDirtyRegionCollection->GetMostSendingPidWhenDisplayNodeSkip();
    EXPECT_TRUE(res2 == 1);
}

/**
 * @tc.name: AddUpdateCacheSurfaceCountForDFX001
 * @tc.desc: AddUpdateCacheSurfaceCountForDFX increments updateCacheSurfaceCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GpuDirtyRegionCollectionTest, AddUpdateCacheSurfaceCountForDFX001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    ASSERT_NE(gpuDirtyRegionCollection, nullptr);
    EXPECT_EQ(gpuDirtyRegionCollection->globalDirtyRegionInfo_.updateCacheSurfaceCount, 0);

    gpuDirtyRegionCollection->AddUpdateCacheSurfaceCountForDFX();
    EXPECT_EQ(gpuDirtyRegionCollection->globalDirtyRegionInfo_.updateCacheSurfaceCount, 1);

    gpuDirtyRegionCollection->AddUpdateCacheSurfaceCountForDFX();
    EXPECT_EQ(gpuDirtyRegionCollection->globalDirtyRegionInfo_.updateCacheSurfaceCount, 2);
}

/**
 * @tc.name: AddSkipCommitFramesForDFX001
 * @tc.desc: AddSkipCommitFramesForDFX increments skipCommitFrames
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GpuDirtyRegionCollectionTest, AddSkipCommitFramesForDFX001, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    ASSERT_NE(gpuDirtyRegionCollection, nullptr);
    EXPECT_EQ(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipCommitFrames, 0);

    gpuDirtyRegionCollection->AddSkipCommitFramesForDFX();
    EXPECT_EQ(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipCommitFrames, 1);

    gpuDirtyRegionCollection->AddSkipCommitFramesForDFX();
    EXPECT_EQ(gpuDirtyRegionCollection->globalDirtyRegionInfo_.skipCommitFrames, 2);
}

/**
 * @tc.name: GetGlobalDirtyRegionInfo002
 * @tc.desc: GetGlobalDirtyRegionInfo returns updateCacheSurfaceCount and skipCommitFrames fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GpuDirtyRegionCollectionTest, GetGlobalDirtyRegionInfo002, TestSize.Level1)
{
    std::shared_ptr<GpuDirtyRegionCollection> gpuDirtyRegionCollection = std::make_shared<GpuDirtyRegionCollection>();
    ASSERT_NE(gpuDirtyRegionCollection, nullptr);

    constexpr int32_t EXPECTED_CACHE_COUNT = 3;
    constexpr int32_t EXPECTED_SKIP_COUNT = 2;
    for (int32_t i = 0; i < EXPECTED_CACHE_COUNT; i++) {
        gpuDirtyRegionCollection->AddUpdateCacheSurfaceCountForDFX();
    }
    for (int32_t i=0; i<EXPECTED_SKIP_COUNT; i++) {
        gpuDirtyRegionCollection->AddSkipCommitFramesForDFX();
    }

    auto info = gpuDirtyRegionCollection->GetGlobalDirtyRegionInfo();
    EXPECT_EQ(info.updateCacheSurfaceCount, EXPECTED_CACHE_COUNT);
    EXPECT_EQ(info.skipCommitFrames, EXPECTED_SKIP_COUNT);
}

/**
 * @tc.name: GlobalDirtyRegionInfoOperatorAdd001
 * @tc.desc: GlobalDirtyRegionInfo operator+= accumulates updateCacheSurfaceCount and skipCommitFrames
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GpuDirtyRegionCollectionTest, GlobalDirtyRegionInfoOperatorAdd001, TestSize.Level1)
{
    constexpr int64_t AREA_1 = 100;
    constexpr int64_t AREA_2 = 200;
    constexpr int32_t FRAMES_1 = 1;
    constexpr int32_t FRAMES_2 = 2;
    constexpr int32_t SKIP_1 = 1;
    constexpr int32_t SKIP_2 = 3;
    constexpr int32_t CMD_1 = 5;
    constexpr int32_t CMD_2 = 7;
    constexpr int32_t BUF_1 = 10;
    constexpr int32_t BUF_2 = 20;
    constexpr int32_t ANIM_1 = 1;
    constexpr int32_t ANIM_2 = 4;
    constexpr pid_t PID_1 = 100;
    constexpr pid_t PID_2 = 200;
    constexpr int32_t CACHE_1 = 3;
    constexpr int32_t CACHE_2 = 5;
    constexpr int32_t SKIP_COMMIT_1 = 2;
    constexpr int32_t SKIP_COMMIT_2 = 6;

    GlobalDirtyRegionInfo lhs(AREA_1, FRAMES_1, SKIP_1, CMD_1, BUF_1, ANIM_1, PID_1, CACHE_1, SKIP_COMMIT_1);
    GlobalDirtyRegionInfo rhs(AREA_2, FRAMES_2, SKIP_2, CMD_2, BUF_2, ANIM_2, PID_2, CACHE_2, SKIP_COMMIT_2);
    lhs += rhs;
    
    EXPECT_EQ(lhs.updateCacheSurfaceCount, CACHE_1 + CACHE_2);
    EXPECT_EQ(lhs.skipCommitFrames, SKIP_COMMIT_1 + SKIP_COMMIT_2);
    EXPECT_EQ(lhs.globalFramesNumber, FRAMES_1 + FRAMES_2);
    EXPECT_EQ(lhs.globalDirtyRegionAreas, AREA_1 + AREA_2);
}
} // namespace OHOS::Rosen
