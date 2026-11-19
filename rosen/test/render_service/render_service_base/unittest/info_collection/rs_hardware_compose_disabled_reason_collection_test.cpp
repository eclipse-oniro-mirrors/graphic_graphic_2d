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

#include <cinttypes>

#include "gtest/gtest.h"

#include "info_collection/rs_hardware_compose_disabled_reason_collection.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr NodeId TEST_NODE_ID_1 = 1001;
constexpr NodeId TEST_NODE_ID_2 = 1002;
constexpr NodeId TEST_NODE_ID_3 = 1003;
constexpr NodeId TEST_NODE_ID_4 = 1004;
constexpr NodeId TEST_NODE_ID_5 = 1005;
constexpr NodeId TEST_NODE_ID_6 = 1006;
constexpr NodeId TEST_NODE_ID_7 = 1007;
constexpr NodeId TEST_PARENT_ID = 999;
constexpr int32_t TEST_BUFFER_WIDTH = 1080;
constexpr int32_t TEST_BUFFER_HEIGHT = 1920;
constexpr float TEST_BOUNDS_WIDTH = 1080.0f;
constexpr float TEST_BOUNDS_HEIGHT = 1920.0f;
constexpr float TEST_BRIGHTNESS_FACTOR = 0.5f;
constexpr int32_t TEST_FLAG_ENABLED = 1;
constexpr int32_t INVALID_REASON_NEGATIVE = -1;
constexpr int32_t EXPECTED_INFO_SIZE_1 = 1;
constexpr int32_t ENUM_VALUE_25 = 25;
constexpr int32_t ENUM_VALUE_26 = 26;
constexpr int32_t ENUM_VALUE_27 = 27;
constexpr int32_t ENUM_VALUE_28 = 28;
constexpr int32_t ENUM_VALUE_29 = 29;
constexpr int32_t ENUM_VALUE_30 = 30;
constexpr int32_t ENUM_VALUE_31 = 31;
constexpr int32_t ENUM_VALUE_32 = 32;
constexpr int32_t ENUM_VALUE_33 = 33;
constexpr int32_t ENUM_VALUE_34 = 34;
constexpr int32_t ENUM_VALUE_35 = 35;
constexpr int32_t ENUM_VALUE_36 = 36;
constexpr int32_t ENUM_VALUE_37 = 37;
constexpr int32_t ENUM_VALUE_38 = 38;
constexpr int32_t ENUM_VALUE_39 = 39;
}
class RsHardwareComposeDisabledReasonCollectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RsHardwareComposeDisabledReasonCollectionTest::SetUpTestCase() {}
void RsHardwareComposeDisabledReasonCollectionTest::TearDownTestCase() {}
void RsHardwareComposeDisabledReasonCollectionTest::SetUp()
{
    HwcDisabledReasonCollection::GetInstance().GetHwcDisabledReasonInfo();
}
void RsHardwareComposeDisabledReasonCollectionTest::TearDown()
{
    HwcDisabledReasonCollection::GetInstance().GetHwcDisabledReasonInfo();
}

/**
 * @tc.name: UpdateHwcDisabledReasonForDFX001
 * @tc.desc: UpdateHwcDisabledReasonForDFX test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, UpdateHwcDisabledReasonForDFX001, TestSize.Level1)
{
    auto& hardwareComposeDisabledReasonCollection = HwcDisabledReasonCollection::GetInstance();
    auto originDisabledReasonInfoMapSize = hardwareComposeDisabledReasonCollection.GetHwcDisabledReasonInfo().size();

    NodeId id = 0;
    int32_t disabledReason = 1;
    std::string nodeName = "node";
    hardwareComposeDisabledReasonCollection.UpdateHwcDisabledReasonForDFX(id, disabledReason, nodeName);
    ++originDisabledReasonInfoMapSize;
    EXPECT_TRUE(hardwareComposeDisabledReasonCollection.GetHwcDisabledReasonInfo().size() ==
        originDisabledReasonInfoMapSize);

    disabledReason = -1;
    ++originDisabledReasonInfoMapSize;
    hardwareComposeDisabledReasonCollection.UpdateHwcDisabledReasonForDFX(id, disabledReason, nodeName);
    EXPECT_FALSE(hardwareComposeDisabledReasonCollection.GetHwcDisabledReasonInfo().size() ==
        originDisabledReasonInfoMapSize);

    disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_REASON_LENGTH);
    ++originDisabledReasonInfoMapSize;
    hardwareComposeDisabledReasonCollection.UpdateHwcDisabledReasonForDFX(id, disabledReason, nodeName);
    EXPECT_FALSE(hardwareComposeDisabledReasonCollection.GetHwcDisabledReasonInfo().size() ==
        originDisabledReasonInfoMapSize);
}

/**
 * @tc.name: RecordHwcDisabledWithTrace001
 * @tc.desc: RecordHwcDisabledWithTrace with valid reason and format args
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace001, TestSize.Level1)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_1;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_FORCE_DISABLE_HDR);
    std::string nodeName = "testNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "disabled by HDR brightnessFactor:%f", TEST_BRIGHTNESS_FACTOR);

    auto infos = collection.GetHwcDisabledReasonInfo();
    ASSERT_EQ(infos.size(), static_cast<size_t>(EXPECTED_INFO_SIZE_1));
    EXPECT_EQ(infos[0].nodeName, nodeName);
    EXPECT_GT(infos[0].disabledReasonStatistics[disabledReason], 0);
}

/**
 * @tc.name: RecordHwcDisabledWithTrace002
 * @tc.desc: RecordHwcDisabledWithTrace with no format args
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace002, TestSize.Level1)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_2;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_3D_GLASS_FREE);
    std::string nodeName = "glassFreeNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
         "disabled by glass free 3d layer");

    auto infos = collection.GetHwcDisabledReasonInfo();
    ASSERT_EQ(infos.size(), static_cast<size_t>(EXPECTED_INFO_SIZE_1));
    EXPECT_EQ(infos[0].nodeName, nodeName);
    EXPECT_GT(infos[0].disabledReasonStatistics[disabledReason], 0);
}

/**
 * @tc.name: RecordHwcDisabledWithTrace003
 * @tc.desc: RecordHwcDisabledWithTrace with invalid reason (negative)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace003, TestSize.Level2)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_3;
    int32_t disabledReason = INVALID_REASON_NEGATIVE;
    std::string nodeName = "invalidNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "disabled by invalid reason");
    
    auto infos = collection.GetHwcDisabledReasonInfo();
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: RecordHwcDisabledWithTrace004
 * @tc.desc: RecordHwcDisabledWithTrace with invalid reason (out of range)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace004, TestSize.Level2)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_4;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_REASON_LENGTH);
    std::string nodeName = "outOfRangeNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "disabled by out of range reason");
    
    auto infos = collection.GetHwcDisabledReasonInfo();
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: RecordHwcDisabledWithTrace005
 * @tc.desc: RecordHwcDisabledWithTrace with multiple format args
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace005, TestSize.Level1)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_5;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_BUFFER_NONMATCH);
    std::string nodeName = "bufferNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "parentId:%" PRIu64 " buffer:[%d,%d] bounds:[%f,%f] disabled by buffer nonmatching",
        static_cast<uint64_t>(TEST_PARENT_ID), TEST_BUFFER_WIDTH, TEST_BUFFER_HEIGHT,
        TEST_BOUNDS_WIDTH, TEST_BOUNDS_HEIGHT);

    auto infos = collection.GetHwcDisabledReasonInfo();
    ASSERT_EQ(infos.size(), static_cast<size_t>(EXPECTED_INFO_SIZE_1));
    EXPECT_EQ(infos[0].nodeName, nodeName);
    EXPECT_GT(infos[0].disabledReasonStatistics[disabledReason], 0);
}

/**
 * @tc.name: RecordHwcDisabledWithTrace006
 * @tc.desc: RecordHwcDisabledWithTrace with new enum DISABLED_BY_RENDERFIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace006, TestSize.Level1)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_6;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_RENDERFIT);
    std::string nodeName = "renderfitNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "disabled by renderfit, isFrameGravityNewVersionEnabled:%d", TEST_FLAG_ENABLED);

    auto infos = collection.GetHwcDisabledReasonInfo();
    ASSERT_EQ(infos.size(), static_cast<size_t>(EXPECTED_INFO_SIZE_1));
    EXPECT_GT(infos[0].disabledReasonStatistics[disabledReason], 0);
}

/**
 * @tc.name: RecordHwcDisabledWithTrace007
 * @tc.desc: RecordHwcDisabledWithTrace with new enum DISABLED_BY_OTHERS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace007, TestSize.Level1)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_7;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_OTHERS);
    std::string nodeName = "otherNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "disabled by other reasons");

    auto infos = collection.GetHwcDisabledReasonInfo();
    ASSERT_EQ(infos.size(), static_cast<size_t>(EXPECTED_INFO_SIZE_1));
    EXPECT_GT(infos[0].disabledReasonStatistics[disabledReason], 0);
}

/**
 * @tc.name: HwcDisabledReasonEnum001
 * @tc.desc: Verify new enum values are correctly defined
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, HwcDisabledReasonEnum001, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_FORCE_DISABLE_HDR), ENUM_VALUE_25);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_3D_GLASS_FREE), ENUM_VALUE_26);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_ANCO_GLOBAL_POSITION), ENUM_VALUE_27);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_ANCO_DIMMING_NODE_BELOW), ENUM_VALUE_28);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_DELEGATE_MODE), ENUM_VALUE_29);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_SUBTREE_SKIPPED_OCCLUDED), ENUM_VALUE_30);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_GPU_OFFLINE_NOT_READY), ENUM_VALUE_31);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_NO_BUFFER_IN_SKIPPEDBUFFER), ENUM_VALUE_32);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_FRAME_GRAVITY), ENUM_VALUE_33);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_SCALING_MODE), ENUM_VALUE_34);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_RENDERFIT), ENUM_VALUE_35);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_ACCUMULATE_BUFFER_FRAME_TIME_INTERVALS),
        ENUM_VALUE_36);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_TRANSPARENT_LAYER_ABOVE), ENUM_VALUE_37);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_OTHERS), ENUM_VALUE_38);
    EXPECT_EQ(static_cast<int32_t>(HwcDisabledReasons::DISABLED_REASON_LENGTH), ENUM_VALUE_39);
}

/**
 * @tc.name: RecordHwcDisabledWithTrace008
 * @tc.desc: RecordHwcDisabledWithTrace with new enum DISABLED_BY_TRANSPARENT_LAYER_ABOVE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsHardwareComposeDisabledReasonCollectionTest, RecordHwcDisabledWithTrace008, TestSize.Level1)
{
    auto& collection = HwcDisabledReasonCollection::GetInstance();
    collection.GetHwcDisabledReasonInfo();

    NodeId id = TEST_NODE_ID_7;
    int32_t disabledReason = static_cast<int32_t>(HwcDisabledReasons::DISABLED_BY_TRANSPARENT_LAYER_ABOVE);
    std::string nodeName = "transparentLayerNode";
    collection.RecordHwcDisabledWithTrace(id, disabledReason, nodeName,
        "disabled by transparent layer above");

    auto infos = collection.GetHwcDisabledReasonInfo();
    ASSERT_EQ(infos.size(), static_cast<size_t>(EXPECTED_INFO_SIZE_1));
    EXPECT_EQ(infos[0].nodeName, nodeName);
    EXPECT_GT(infos[0].disabledReasonStatistics[disabledReason], 0);
}
} // namespace OHOS::Rosen
