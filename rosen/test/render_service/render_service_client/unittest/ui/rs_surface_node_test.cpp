/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "parameters.h"
#include "ui/rs_surface_node.h"
#include "limit_number.h"

using namespace testing;
using namespace testing::ext;
static constexpr uint32_t FIRST_COLOR_VALUE = 0x034123;
static constexpr uint32_t SECOND_COLOR_VALUE = 0x45ba87;
static constexpr uint32_t THIRD_COLOR_VALUE = 0x32aadd;
namespace OHOS::Rosen {
class RSSurfaceNodeTest : public testing::Test {
public:
    constexpr static float floatData[] = {
        0.0f, 485.44f, -34.4f,
        std::numeric_limits<float>::max(), std::numeric_limits<float>::min(),
        };
    static constexpr float outerRadius = 30.4f;
    RRect rrect = RRect({0, 0, 0, 0}, outerRadius, outerRadius);
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSurfaceNodeTest::SetUpTestCase() {}
void RSSurfaceNodeTest::TearDownTestCase() {}
void RSSurfaceNodeTest::SetUp() {}
void RSSurfaceNodeTest::TearDown() {}

/**
 * @tc.name: CreateNodeInRenderThread001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, CreateNodeInRenderThread001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);

    surfaceNode->CreateNodeInRenderThread();
}

/**
 * @tc.name: SetBufferAvailableCallback001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetBufferAvailableCallback001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);

    bool isSuccess = surfaceNode->SetBufferAvailableCallback([]() {
        std::cout << "SetBufferAvailableCallback" << std::endl;
    });
    ASSERT_TRUE(isSuccess);
}

/**
 * @tc.name: SetandGetBounds001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBounds001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBounds(TestSrc::limitNumber::floatLimit[0], TestSrc::limitNumber::floatLimit[1],
        TestSrc::limitNumber::floatLimit[2], TestSrc::limitNumber::floatLimit[3]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.x_, TestSrc::limitNumber::floatLimit[0]));
    EXPECT_TRUE(ROSEN_EQ(bounds.y_, TestSrc::limitNumber::floatLimit[1]));
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[2]));
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[3]));
}

/**
 * @tc.name: SetandGetBounds002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBounds002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBounds(TestSrc::limitNumber::floatLimit[3], TestSrc::limitNumber::floatLimit[1],
        TestSrc::limitNumber::floatLimit[2], TestSrc::limitNumber::floatLimit[0]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.x_, TestSrc::limitNumber::floatLimit[3]));
    EXPECT_TRUE(ROSEN_EQ(bounds.y_, TestSrc::limitNumber::floatLimit[1]));
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[2]));
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[0]));
}

/**
 * @tc.name: SetandGetBounds003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBounds003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBounds(TestSrc::limitNumber::floatLimit[3], TestSrc::limitNumber::floatLimit[2],
        TestSrc::limitNumber::floatLimit[1], TestSrc::limitNumber::floatLimit[0]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.x_, TestSrc::limitNumber::floatLimit[3]));
    EXPECT_TRUE(ROSEN_EQ(bounds.y_, TestSrc::limitNumber::floatLimit[2]));
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[1]));
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[0]));
}

/**
 * @tc.name: SetandGetBounds004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBounds004, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    Vector4f quaternion(TestSrc::limitNumber::floatLimit[0], TestSrc::limitNumber::floatLimit[1],
        TestSrc::limitNumber::floatLimit[2], TestSrc::limitNumber::floatLimit[3]);
    surfaceNode->SetBounds(quaternion);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.x_, TestSrc::limitNumber::floatLimit[0]));
    EXPECT_TRUE(ROSEN_EQ(bounds.y_, TestSrc::limitNumber::floatLimit[1]));
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[2]));
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[3]));
}

/**
 * @tc.name: SetandGetBounds005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBounds005, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    Vector4f quaternion(TestSrc::limitNumber::floatLimit[3], TestSrc::limitNumber::floatLimit[1],
        TestSrc::limitNumber::floatLimit[2], TestSrc::limitNumber::floatLimit[0]);
    surfaceNode->SetBounds(quaternion);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.x_, TestSrc::limitNumber::floatLimit[3]));
    EXPECT_TRUE(ROSEN_EQ(bounds.y_, TestSrc::limitNumber::floatLimit[1]));
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[2]));
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[0]));
}

/**
 * @tc.name: SetandGetBounds006
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBounds006, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    Vector4f quaternion(TestSrc::limitNumber::floatLimit[3], TestSrc::limitNumber::floatLimit[2],
        TestSrc::limitNumber::floatLimit[1], TestSrc::limitNumber::floatLimit[0]);
    surfaceNode->SetBounds(quaternion);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.x_, TestSrc::limitNumber::floatLimit[3]));
    EXPECT_TRUE(ROSEN_EQ(bounds.y_, TestSrc::limitNumber::floatLimit[2]));
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[1]));
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[0]));
}

/**
 * @tc.name: SetandGetBoundsWidth001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsWidth001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsWidth(TestSrc::limitNumber::floatLimit[1]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[1]));
}

/**
 * @tc.name: SetandGetBoundsWidth002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsWidth002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsWidth(TestSrc::limitNumber::floatLimit[2]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[2]));
}

/**
 * @tc.name: SetandGetBoundsWidth003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsWidth003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsWidth(TestSrc::limitNumber::floatLimit[3]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[3]));
}

/**
 * @tc.name: SetandGetBoundsWidth004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsWidth004, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsWidth(TestSrc::limitNumber::floatLimit[4]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[4]));
}

/**
 * @tc.name: SetandGetBoundsWidth005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsWidth005, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsWidth(TestSrc::limitNumber::floatLimit[0]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.z_, TestSrc::limitNumber::floatLimit[0]));
}

/**
 * @tc.name: SetandGetBoundsHeight001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsHeight001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsHeight(TestSrc::limitNumber::floatLimit[1]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[1]));
}

/**
 * @tc.name: SetandGetBoundsHeight002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsHeight002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsHeight(TestSrc::limitNumber::floatLimit[2]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[2]));
}

/**
 * @tc.name: SetandGetBoundsHeight003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsHeight003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsHeight(TestSrc::limitNumber::floatLimit[3]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[3]));
}

/**
 * @tc.name: SetandGetBoundsHeight004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsHeight004, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsHeight(TestSrc::limitNumber::floatLimit[4]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[4]));
}

/**
 * @tc.name: SetandGetBoundsHeight005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetandGetBoundsHeight005, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBoundsHeight(TestSrc::limitNumber::floatLimit[0]);
    auto bounds = surfaceNode->GetStagingProperties().GetBounds();
    EXPECT_TRUE(ROSEN_EQ(bounds.w_, TestSrc::limitNumber::floatLimit[0]));
}

/**
 * @tc.name: SetWatermarkEnabled
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetWatermarkEnabled001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    std::string waterMark = "watermark";
    surfaceNode->SetWatermarkEnabled(waterMark, true);
    surfaceNode->SetWatermarkEnabled(waterMark, false);
    std::string waterMark1(129, 't');
    surfaceNode->SetWatermarkEnabled(waterMark1, false);
}

/**
 * @tc.name: SetSecurityLayer001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetSecurityLayer001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSecurityLayer(true);
    EXPECT_TRUE(surfaceNode->GetSecurityLayer());
}

/**
 * @tc.name: SetSecurityLayer002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetSecurityLayer002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSecurityLayer(false);
    EXPECT_FALSE(surfaceNode->GetSecurityLayer());
}

/**
 * @tc.name: GetSecurityLayer001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, GetSecurityLayer001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    EXPECT_FALSE(surfaceNode->GetSecurityLayer());
}

/**
 * @tc.name: SetSKipLayer001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetSkipLayer001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSkipLayer(true);
    EXPECT_TRUE(surfaceNode->GetSkipLayer());
}

/**
 * @tc.name: SetLeashPersistId001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetLeashPersistId001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    LeashPersistentId leashPersistentId = 50;
    surfaceNode->SetLeashPersistentId(leashPersistentId);
    EXPECT_TRUE(surfaceNode->GetLeashPersistentId() == leashPersistentId);
}

/**
 * @tc.name: SetSnapshotSKipLayer001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetSnapshotSkipLayer001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSnapshotSkipLayer(true);
    EXPECT_TRUE(surfaceNode->GetSnapshotSkipLayer());
}

/**
 * @tc.name: SetSkipLayer002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetSkipLayer002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSkipLayer(false);
    EXPECT_FALSE(surfaceNode->GetSkipLayer());
}

/**
 * @tc.name: SetSnapshotSkipLayer002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, SetSnapshotSkipLayer002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSnapshotSkipLayer(false);
    EXPECT_FALSE(surfaceNode->GetSnapshotSkipLayer());
}

/**
 * @tc.name: GetSkipLayer001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, GetSkipLayer001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    EXPECT_FALSE(surfaceNode->GetSkipLayer());
}

/**
 * @tc.name: GetSnapshotSkipLayer001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, GetSnapshotSkipLayer001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    EXPECT_FALSE(surfaceNode->GetSnapshotSkipLayer());
}

/**
 * @tc.name: Marshalling001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, Marshalling001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);

    Parcel parcel;
    surfaceNode->Marshalling(parcel);
}

/**
 * @tc.name: Marshalling002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, Marshalling002, TestSize.Level1)
{
    Parcel parcel;
    auto surfaceNode = RSSurfaceNode::Unmarshalling(parcel);
    EXPECT_TRUE(surfaceNode == nullptr);
}

/**
 * @tc.name: Marshalling003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, Marshalling003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);

    Parcel parcel;
    surfaceNode->Marshalling(parcel);
    RSSurfaceNode::Unmarshalling(parcel);
}

/**
 * @tc.name: Marshalling004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, Marshalling004, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);

    Parcel parcel;
    surfaceNode->Marshalling(parcel);
    RSSurfaceNode::Unmarshalling(parcel);
    RSSurfaceNode::Unmarshalling(parcel);
}

/**
 * @tc.name: Marshalling005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, Marshalling005, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode1 = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode1 != nullptr);
    RSSurfaceNode::SharedPtr surfaceNode2 = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode2 != nullptr);

    Parcel parcel;
    surfaceNode1->Marshalling(parcel);
    surfaceNode2->Marshalling(parcel);
    RSSurfaceNode::Unmarshalling(parcel);
}

/**
 * @tc.name: GetSurface001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, GetSurface001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);

    surfaceNode->GetSurface();
}

/**
 * @tc.name: GetType001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSSurfaceNodeTest, GetType001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;

    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);
    ASSERT_TRUE(surfaceNode->GetType() == RSUINodeType::SURFACE_NODE);
}

/**
 * @tc.name: SetCornerRadius001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetCornerRadius001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetCornerRadius(floatData[0]);
    ASSERT_TRUE(surfaceNode != nullptr);
    auto result = surfaceNode->GetStagingProperties().GetCornerRadius()[0];
    EXPECT_TRUE(ROSEN_EQ(floatData[0], result));
}

/**
 * @tc.name: SetCornerRadius002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetCornerRadius002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetCornerRadius(floatData[1]);
    ASSERT_TRUE(surfaceNode != nullptr);
    auto result = surfaceNode->GetStagingProperties().GetCornerRadius()[1];
    EXPECT_TRUE(ROSEN_EQ(floatData[1], result));
}

/**
 * @tc.name: SetCornerRadius003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetCornerRadius003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetCornerRadius(floatData[2]);
    ASSERT_TRUE(surfaceNode != nullptr);
    auto result = surfaceNode->GetStagingProperties().GetCornerRadius()[2];
    EXPECT_TRUE(ROSEN_EQ(floatData[2], result));
}

/**
 * @tc.name: SetBackgroundFilter001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetBackgroundFilter001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::shared_ptr<RSFilter> backgroundFilter = RSFilter::CreateBlurFilter(floatData[0],
    floatData[1]);
    surfaceNode->SetBackgroundFilter(backgroundFilter);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetBackgroundBlurRadiusX() == floatData[0]);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetBackgroundBlurRadiusY() == floatData[1]);
}

/**
 * @tc.name: SetBackgroundFilter002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetBackgroundFilter002, TestSize.Level2)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::shared_ptr<RSFilter> backgroundFilter = RSFilter::CreateBlurFilter(floatData[1],
    floatData[2]);
    surfaceNode->SetBackgroundFilter(backgroundFilter);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetBackgroundBlurRadiusX() == floatData[1]);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetBackgroundBlurRadiusY() == floatData[2]);
}

/**
 * @tc.name: SetBackgroundFilter003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetBackgroundFilter003, TestSize.Level3)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::shared_ptr<RSFilter> backgroundFilter = RSFilter::CreateBlurFilter(floatData[2],
    floatData[3]);
    surfaceNode->SetBackgroundFilter(backgroundFilter);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetBackgroundBlurRadiusX() == floatData[2]);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetBackgroundBlurRadiusY() == floatData[3]);
}

/**
 * @tc.name: SetFilter001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetFilter001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::shared_ptr<RSFilter> filter = RSFilter::CreateBlurFilter(floatData[0],
    floatData[1]);
    surfaceNode->SetFilter(filter);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetForegroundBlurRadiusX() == floatData[0]);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetForegroundBlurRadiusY() == floatData[1]);
}

/**
 * @tc.name: SetFilter002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetFilter002, TestSize.Level2)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::shared_ptr<RSFilter> filter = RSFilter::CreateBlurFilter(floatData[1],
    floatData[2]);
    surfaceNode->SetFilter(filter);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetForegroundBlurRadiusX() == floatData[1]);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetForegroundBlurRadiusY() == floatData[2]);
}

/**
 * @tc.name: SetFilter003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetFilter003, TestSize.Level3)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::shared_ptr<RSFilter> filter = RSFilter::CreateBlurFilter(floatData[2],
    floatData[3]);
    surfaceNode->SetFilter(filter);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetForegroundBlurRadiusX() == floatData[2]);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetForegroundBlurRadiusY() == floatData[3]);
}

/**
 * @tc.name: SetCompositingFilter001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetCompositingFilter001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);
    auto compositingFilter = RSFilter::CreateBlurFilter(floatData[0],
    floatData[1]);
    surfaceNode->SetCompositingFilter(compositingFilter);
}

/**
 * @tc.name: SetCompositingFilter002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetCompositingFilter002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);
    auto compositingFilter = RSFilter::CreateBlurFilter(floatData[1],
    floatData[2]);
    surfaceNode->SetCompositingFilter(compositingFilter);
}

/**
 * @tc.name: SetCompositingFilter003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetCompositingFilter003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode != nullptr);
    auto compositingFilter = RSFilter::CreateBlurFilter(floatData[2],
    floatData[3]);
    surfaceNode->SetCompositingFilter(compositingFilter);
}

/**
 * @tc.name: SetShadowOffset001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffset001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffset(floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetY(), floatData[3]));
}

/**
 * @tc.name: SetShadowOffset002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffset002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffset(floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetY(), floatData[0]));
}

/**
 * @tc.name: SetShadowOffset003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffset003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffset(floatData[1], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetX(), floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetY(), floatData[3]));
}
/**
 * @tc.name: SetShadowOffsetX001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffsetX001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffsetX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetX(), floatData[1]));
}

/**
 * @tc.name: SetShadowOffsetX002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffsetX002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffsetX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetX(), floatData[2]));
}

/**
 * @tc.name: SetShadowOffsetX003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffsetX003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffsetX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetX(), floatData[3]));
}

/**
 * @tc.name: SetShadowOffsetY001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffsetY001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffsetY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetY(), floatData[1]));
}

/**
 * @tc.name: SetShadowOffsetY002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffsetY002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffsetY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetY(), floatData[2]));
}

/**
 * @tc.name: SetShadowOffsetY003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowOffsetY003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowOffsetY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowOffsetY(), floatData[3]));
}

/**
 * @tc.name: SetShadowAlpha001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowAlpha001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowAlpha(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowAlpha(), floatData[1]));
}

/**
 * @tc.name: SetShadowAlpha002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowAlpha002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowAlpha(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowAlpha(), floatData[2]));
}

/**
 * @tc.name: SetShadowAlpha003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowAlpha003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowAlpha(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowAlpha(), floatData[3]));
}

/**
 * @tc.name: SetShadowElevation001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowElevation001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowElevation(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowElevation(), floatData[1]));
}

/**
 * @tc.name: SetShadowElevation002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowElevation002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowElevation(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowElevation(), floatData[2]));
}

/**
 * @tc.name: SetShadowElevation003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowElevation003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowElevation(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowElevation(), floatData[3]));
}

/**
 * @tc.name: SetShadowRadius001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowRadius001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowRadius(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowRadius(), floatData[1]));
}

/**
 * @tc.name: SetShadowRadius002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowRadius002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowRadius(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowRadius(), floatData[2]));
}

/**
 * @tc.name: SetShadowRadius003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowRadius003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowRadius(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(surfaceNode->GetStagingProperties().GetShadowRadius(), floatData[3]));
}

/**
 * @tc.name: SetShadowColor001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowColor001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowColor(FIRST_COLOR_VALUE);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetShadowColor() == Color::FromArgbInt(FIRST_COLOR_VALUE));
}

/**
 * @tc.name: SetShadowColor002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowColor002, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowColor(SECOND_COLOR_VALUE);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetShadowColor() == Color::FromArgbInt(SECOND_COLOR_VALUE));
}

/**
 * @tc.name: SetShadowColor003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetShadowColor003, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetShadowColor(THIRD_COLOR_VALUE);
    EXPECT_TRUE(surfaceNode->GetStagingProperties().GetShadowColor() == Color::FromArgbInt(THIRD_COLOR_VALUE));
}

/**
 * @tc.name: SetFreeze001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetFreeze001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetFreeze(true);
}

/**
 * @tc.name: SetContainerWindow001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetContainerWindow001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetContainerWindow(true, rrect);
}

/**
 * @tc.name: SetIsNotifyUIBufferAvailable001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, SetIsNotifyUIBufferAvailable001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetIsNotifyUIBufferAvailable(true);
}

/**
 * @tc.name: ClearChildren001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issueI5J8R1
 */
HWTEST_F(RSSurfaceNodeTest, ClearChildren001, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->CreateNodeInRenderThread();
    RSSurfaceNodeConfig c2;
    RSSurfaceNode::SharedPtr surfaceNode2 = RSSurfaceNode::Create(c2);
    surfaceNode->AddChild(surfaceNode2, -1);
    surfaceNode->RemoveChild(surfaceNode2);
    surfaceNode->ClearChildren();
}

/**
 * @tc.name: SetFreeze Test True
 * @tc.desc: SetFreeze Test True
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceNodeTest, SetFreeze_True, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetFreeze(true);
}

/**
 * @tc.name: SetFreeze Test False
 * @tc.desc: SetFreeze Test False
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceNodeTest, SetFreeze_False, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetFreeze(false);
}

/**
 * @tc.name: SetContainerWindow Test True
 * @tc.desc: SetContainerWindow Test True
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceNodeTest, SetContainerWindow_True, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetContainerWindow(true, rrect);
}

/**
 * @tc.name: SetContainerWindow Test False
 * @tc.desc: SetContainerWindow Test False
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceNodeTest, SetContainerWindow_False, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetContainerWindow(false, rrect);
}

/**
 * @tc.name: Fingerprint Test
 * @tc.desc: SetFingerprint and GetFingerprint
 * @tc.type: FUNC
 * @tc.require: issueI6Z3YK
 */
HWTEST_F(RSSurfaceNodeTest, Fingerprint, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetFingerprint(true);
    ASSERT_EQ(true, surfaceNode->GetFingerprint());
    surfaceNode->SetFingerprint(false);
    ASSERT_EQ(false, surfaceNode->GetFingerprint());
}

/**
 * @tc.name: SetBootAnimation Test
 * @tc.desc: SetBootAnimation and GetBootAnimation
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetBootAnimationTest, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetBootAnimation(true);
    ASSERT_EQ(true, surfaceNode->GetBootAnimation());
    surfaceNode->SetBootAnimation(false);
    ASSERT_EQ(false, surfaceNode->GetBootAnimation());
}

/**
 * @tc.name: SetGlobalPositionEnabled Test
 * @tc.desc: SetGlobalPositionEnabled and GetGlobalPositionEnabled
 * @tc.type: FUNC
 * @tc.require: issueIATYMW
 */
HWTEST_F(RSSurfaceNodeTest, SetGlobalPositionEnabled, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetGlobalPositionEnabled(true);
    ASSERT_EQ(true, surfaceNode->GetGlobalPositionEnabled());
    surfaceNode->SetGlobalPositionEnabled(false);
    ASSERT_EQ(false, surfaceNode->GetGlobalPositionEnabled());
}

/**
 * @tc.name: IsBufferAvailableTest Test
 * @tc.desc: test results of IsBufferAvailable
 * @tc.type: FUNC
 * @tc.require:issueI9MWJR
 */
HWTEST_F(RSSurfaceNodeTest, IsBufferAvailableTest, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_FALSE(surfaceNode->IsBufferAvailable());
}

/**
 * @tc.name: SetBoundsChangedCallbacktest Test
 * @tc.desc: test results of SetBoundsChangedCallback
 * @tc.type: FUNC
 * @tc.require:issueI9MWJR
 */
HWTEST_F(RSSurfaceNodeTest, SetBoundsChangedCallbackTest, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    BoundsChangedCallback callback = [](const Rosen::Vector4f& bounds) {};
    surfaceNode->SetBoundsChangedCallback(callback);
    ASSERT_NE(surfaceNode->boundsChangedCallback_, nullptr);
}

/**
 * @tc.name: SetTextureExport Test
 * @tc.desc: SetTextureExport
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetTextureExport, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetTextureExport(true);
    surfaceNode->SetTextureExport(false);
}

/**
 * @tc.name: SetHardwareEnabled Test
 * @tc.desc: SetHardwareEnabled
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetHardwareEnabled, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetHardwareEnabled(true);
    surfaceNode->SetHardwareEnabled(false);
}

/**
 * @tc.name: DetachToDisplay Test
 * @tc.desc: DetachToDisplay
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, DetachToDisplay, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    uint64_t screenId = 0;
    surfaceNode->DetachToDisplay(screenId);
}

/**
 * @tc.name: AttachToDisplay Test
 * @tc.desc: AttachToDisplay
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, AttachToDisplay, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    uint64_t screenId = 0;
    surfaceNode->AttachToDisplay(screenId);
}

/**
 * @tc.name: SetAnimationFinished Test
 * @tc.desc: SetAnimationFinished
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetAnimationFinished, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetAnimationFinished();
    ASSERT_FALSE(surfaceNode->isSkipLayer_);
}

/**
 * @tc.name: SetForceHardwareAndFixRotation Test
 * @tc.desc: SetForceHardwareAndFixRotation and SetTextureExport
 * @tc.type: FUNC
 * @tc.require:issueI9MWJR
 */
HWTEST_F(RSSurfaceNodeTest, SetForceHardwareAndFixRotation, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetForceHardwareAndFixRotation(true);
    ASSERT_FALSE(surfaceNode->isSkipLayer_);
    surfaceNode->SetTextureExport(true);
    ASSERT_TRUE(surfaceNode->isTextureExportNode_);
    surfaceNode->SetTextureExport(false);
    ASSERT_FALSE(surfaceNode->isTextureExportNode_);
    surfaceNode->SetTextureExport(false);
    ASSERT_FALSE(surfaceNode->isTextureExportNode_);
}

/**
 * @tc.name: GetColorSpace Test
 * @tc.desc: test results of GetColorSpace
 * @tc.type: FUNC
 * @tc.require:issueI9MWJR
 */
HWTEST_F(RSSurfaceNodeTest, GetColorSpace, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_TRUE(surfaceNode->GetColorSpace() == GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB);
}

/**
 * @tc.name: ResetContextAlpha Test
 * @tc.desc: GetBundleName and ResetContextAlpha
 * @tc.type: FUNC
 * @tc.require:issueI9MWJR
 */
HWTEST_F(RSSurfaceNodeTest, ResetContextAlpha, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->ResetContextAlpha();
    ASSERT_NE(RSTransactionProxy::GetInstance()->implicitRemoteTransactionData_, nullptr);
}

/**
 * @tc.name: SetClonedNodeInfo Test
 * @tc.desc: test results of SetClonedNodeInfo
 * @tc.type: FUNC
 * @tc.require:issueIBX8OW
 */
HWTEST_F(RSSurfaceNodeTest, SetClonedNodeInfo, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetClonedNodeInfo(INVALID_NODEID + 1);
    ASSERT_NE(RSTransactionProxy::GetInstance()->implicitRemoteTransactionData_, nullptr);
}

/**
 * @tc.name: SetForeground Test
 * @tc.desc: SetForeground and SetForceUIFirst and SetAncoFlags and SetHDRPresent
 * @tc.type: FUNC
 * @tc.require:issueI9MWJR
 */
HWTEST_F(RSSurfaceNodeTest, SetForeground, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetForeground(true);
    surfaceNode->SetForceUIFirst(true);
    surfaceNode->SetAncoFlags(1);
    surfaceNode->SetHDRPresent(true, 0);
    ASSERT_NE(RSTransactionProxy::GetInstance()->implicitRemoteTransactionData_, nullptr);
}

/**
 * @tc.name: SetBoundsChangedCallback Test
 * @tc.desc: SetBoundsChangedCallback
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetBoundsChangedCallback, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ASSERT_NE(surfaceNode, nullptr);
    using BoundsChangedCallback = std::function<void(const Rosen::Vector4f&)>;
    BoundsChangedCallback callback;
    surfaceNode->SetBoundsChangedCallback(callback);
}

/**
 * @tc.name: IsBufferAvailable Test
 * @tc.desc: IsBufferAvailable
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, IsBufferAvailable, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    bool ret = surfaceNode->IsBufferAvailable();
    ASSERT_EQ(false, ret);
}

/**
 * @tc.name: MarkUIHidden Test
 * @tc.desc: MarkUIHidden
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, MarkUIHidden, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    bool isHidden = true;
    surfaceNode->MarkUIHidden(isHidden);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SetIsNotifyUIBufferAvailable Test
 * @tc.desc: SetIsNotifyUIBufferAvailable
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetIsNotifyUIBufferAvailable, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    bool available = true;
    surfaceNode->SetIsNotifyUIBufferAvailable(available);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SetAbilityBGAlpha Test
 * @tc.desc: SetAbilityBGAlpha
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetAbilityBGAlpha, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    uint8_t alpha = 0;
    surfaceNode->SetAbilityBGAlpha(alpha);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SetAbilityBGAlpha Test
 * @tc.desc: SetAbilityBGAlpha
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, NeedForcedSendToRemote, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->NeedForcedSendToRemote();
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: CreateNode Test
 * @tc.desc: CreateNode
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, CreateNode, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    const RSSurfaceRenderNodeConfig& config = {0, "SurfaceNode", RSSurfaceNodeType::DEFAULT, nullptr, false, false};
    bool res = surfaceNode->CreateNode(config);
    ASSERT_EQ(true, res);
}

/**
 * @tc.name: CreateNodeAndSurface Test
 * @tc.desc: CreateNodeAndSurface
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, CreateNodeAndSurface, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    const RSSurfaceRenderNodeConfig& config = {0, "SurfaceNode", RSSurfaceNodeType::DEFAULT, nullptr, false, false};
    SurfaceId surfaceId = 0;
    bool res = surfaceNode->CreateNodeAndSurface(config, surfaceId);
    ASSERT_EQ(false, res);
}

/**
 * @tc.name: OnBoundsSizeChanged Test
 * @tc.desc: OnBoundsSizeChanged
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, OnBoundsSizeChanged, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->OnBoundsSizeChanged();
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SetSurfaceIdToRenderNode Test
 * @tc.desc: SetSurfaceIdToRenderNode
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetSurfaceIdToRenderNode, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSurfaceIdToRenderNode();
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: CreateRenderNodeForTextureExportSwitch Test
 * @tc.desc: CreateRenderNodeForTextureExportSwitch
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, CreateRenderNodeForTextureExportSwitch, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->CreateRenderNodeForTextureExportSwitch();
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SetIsTextureExportNode Test
 * @tc.desc: SetIsTextureExportNode
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SetIsTextureExportNode, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    bool isTextureExportNode = true;
    surfaceNode->SetIsTextureExportNode(isTextureExportNode);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SplitSurfaceNodeName Test
 * @tc.desc: SplitSurfaceNodeName
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceNodeTest, SplitSurfaceNodeName, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    std::string surfaceNodeName = "0#1";
    std::pair<std::string, std::string> res = surfaceNode->SplitSurfaceNodeName(surfaceNodeName);
    EXPECT_EQ(res.first, "0");
    EXPECT_EQ(res.second, "1");
}

/**
 * @tc.name: SetColorSpace Test
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceNodeTest, SetColorSpace, TestSize.Level1)
{
    RSSurfaceNodeConfig config;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(config);
    surfaceNode->SetColorSpace(GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB);
    ASSERT_EQ(surfaceNode->colorSpace_, GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB);
}

/**
 * @tc.name: SetSKipDraw
 * @tc.desc: Test function SetSkipDraw
 * @tc.type: FUNC
 * @tc.require: issueI9U6LX
 */
HWTEST_F(RSSurfaceNodeTest, SetSkipDraw, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetSkipDraw(true);
    EXPECT_TRUE(surfaceNode->GetSkipDraw());

    surfaceNode->SetSkipDraw(false);
    EXPECT_FALSE(surfaceNode->GetSkipDraw());
}

/**
 * @tc.name: GetSkipLayer001
 * @tc.desc: Test function GetSkipDraw
 * @tc.type: FUNC
 * @tc.require: issueI9U6LX
 */
HWTEST_F(RSSurfaceNodeTest, GetSkipDraw, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    EXPECT_FALSE(surfaceNode->GetSkipDraw());
}

/**
 * @tc.name: SetAbilityState
 * @tc.desc: Test function SetAbilityState
 * @tc.type: FUNC
 * @tc.require: issueIAQL48
 */
HWTEST_F(RSSurfaceNodeTest, SetAbilityState, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetAbilityState(RSSurfaceNodeAbilityState::FOREGROUND);
    EXPECT_TRUE(surfaceNode->GetAbilityState() == RSSurfaceNodeAbilityState::FOREGROUND);

    surfaceNode->SetAbilityState(RSSurfaceNodeAbilityState::BACKGROUND);
    EXPECT_TRUE(surfaceNode->GetAbilityState() == RSSurfaceNodeAbilityState::BACKGROUND);
}

/**
 * @tc.name: GetAbilityState
 * @tc.desc: Test function GetAbilityState
 * @tc.type: FUNC
 * @tc.require: issueIAQL48
 */
HWTEST_F(RSSurfaceNodeTest, GetAbilityState, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    EXPECT_TRUE(surfaceNode->GetAbilityState() == RSSurfaceNodeAbilityState::FOREGROUND);
}

/**
 * @tc.name: SetHardwareEnableHint
 * @tc.desc: Test function SetHardwareEnableHint
 * @tc.type: FUNC
 * @tc.require: issueIAHFXD
 */
HWTEST_F(RSSurfaceNodeTest, SetHardwareEnableHint, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    surfaceNode->SetHardwareEnableHint(true);
    surfaceNode->SetHardwareEnableHint(false);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: SetSourceVirtualDisplayId
 * @tc.desc: Test function SetSourceVirtualDisplayId
 * @tc.type: FUNC
 * @tc.require: issueIBIK1X
 */
HWTEST_F(RSSurfaceNodeTest, SetSourceVirtualDisplayId, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ScreenId id = {};
    surfaceNode->SetSourceVirtualDisplayId(id);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: AttachToWindowContainer
 * @tc.desc: Test function AttachToWindowContainer
 * @tc.type: FUNC
 * @tc.require: issueIBIK1X
 */
HWTEST_F(RSSurfaceNodeTest, AttachToWindowContainer, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ScreenId id = {};
    surfaceNode->AttachToWindowContainer(id);
    ASSERT_NE(surfaceNode, nullptr);
}

/**
 * @tc.name: DetachFromWindowContainer
 * @tc.desc: Test function DetachFromWindowContainer
 * @tc.type: FUNC
 * @tc.require: issueIBIK1X
 */
HWTEST_F(RSSurfaceNodeTest, DetachFromWindowContainer, TestSize.Level1)
{
    RSSurfaceNodeConfig c;
    RSSurfaceNode::SharedPtr surfaceNode = RSSurfaceNode::Create(c);
    ScreenId id = {};
    surfaceNode->DetachFromWindowContainer(id);
    ASSERT_NE(surfaceNode, nullptr);
}
} // namespace OHOS::Rosen