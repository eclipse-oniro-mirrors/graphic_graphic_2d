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
#include "transaction/rs_interfaces.h"
#include "ui/rs_display_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSDisplayNodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSDisplayNodeTest::SetUpTestCase() {}
void RSDisplayNodeTest::TearDownTestCase() {}
void RSDisplayNodeTest::SetUp() {}
void RSDisplayNodeTest::TearDown() {}

/**
 * @tc.name: Create001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, Create001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSDisplayNode
     */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
}

/**
 * @tc.name: AddDisplayNodeToTree001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, AddDisplayNodeToTree001, TestSize.Level1)
{
    /**
    * @tc.steps: step1. create RSDisplayNode
    */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    displayNode->AddDisplayNodeToTree();
}

/**
 * @tc.name: RemoveDisplayNodeFromTree001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, RemoveDisplayNodeFromTree001, TestSize.Level1)
{
    /**
    * @tc.steps: step1. create RSDisplayNode
    */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    displayNode->RemoveDisplayNodeFromTree();
}

/**
 * @tc.name: GetType001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, GetType001, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    ASSERT_TRUE(displayNode->GetType() == RSUINodeType::DISPLAY_NODE);
}

/**
 * @tc.name: SetSecurityDisplay001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, SetSecurityDisplay001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSDisplayNode
     */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    /**
     * @tc.steps: step2. set SecurityDisplay
     */
    displayNode->SetSecurityDisplay(true);
    EXPECT_TRUE(displayNode->GetSecurityDisplay());
}

/**
 * @tc.name: SetSecurityDisplay002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, SetSecurityDisplay002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSDisplayNode
     */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    /**
     * @tc.steps: step2. set SecurityDisplay
     */
    ASSERT_TRUE(displayNode != nullptr);
    displayNode->SetSecurityDisplay(false);
    EXPECT_FALSE(displayNode->GetSecurityDisplay());
}


/**
 * @tc.name: GetSecurityDisplay001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, GetSecurityDisplay001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSDisplayNode
     */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    EXPECT_FALSE(displayNode->GetSecurityDisplay());
}

/**
 * @tc.name: SetScreenId001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, SetScreenId001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSDisplayNode
     */
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    displayNode->SetScreenId(1);

    delete RSTransactionProxy::instance_;
    RSTransactionProxy::instance_ = nullptr;
    displayNode->SetScreenId(1);
    ASSERT_TRUE(RSTransactionProxy::instance_ == nullptr);
    RSTransactionProxy::instance_ = new RSTransactionProxy();
}

/**
 * @tc.name: ClearChildrenTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, ClearChildrenTest, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);
    displayNode->ClearChildren();

    displayNode->children_.push_back(0);
    displayNode->children_.push_back(1);
    displayNode->children_.push_back(2);
    displayNode->ClearChildren();
    EXPECT_TRUE(!displayNode->children_.empty());
}

/**
 * @tc.name: IsMirrorDisplayTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDisplayNodeTest, IsMirrorDisplayTest, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);
    ASSERT_FALSE(displayNode->IsMirrorDisplay());
}

/**
 * @tc.name: SetBootAnimation Test
 * @tc.desc: SetBootAnimation and GetBootAnimation
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSDisplayNodeTest, SetBootAnimationTest, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    displayNode->SetBootAnimation(true);
    ASSERT_EQ(true, displayNode->GetBootAnimation());
    displayNode->SetBootAnimation(false);
    ASSERT_EQ(false, displayNode->GetBootAnimation());

    delete RSTransactionProxy::instance_;
    RSTransactionProxy::instance_ = nullptr;
    displayNode->SetBootAnimation(false);
    ASSERT_TRUE(RSTransactionProxy::instance_ == nullptr);
    RSTransactionProxy::instance_ = new RSTransactionProxy();
}

/**
 * @tc.name: Marshalling
 * @tc.desc: test results of Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI9KDPI
 */
HWTEST_F(RSDisplayNodeTest, Marshalling, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    Parcel parcel;
    bool res = displayNode->Marshalling(parcel);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Unmarshalling
 * @tc.desc: test results of Unmarshalling
 * @tc.type: FUNC
 * @tc.require: issueI9KDPI
 */
HWTEST_F(RSDisplayNodeTest, Unmarshalling, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    Parcel parcel;
    auto res = displayNode->Unmarshalling(parcel);
    EXPECT_EQ(res, nullptr);
}

/**
 * @tc.name: OnBoundsSizeChanged
 * @tc.desc: test results of OnBoundsSizeChanged
 * @tc.type: FUNC
 * @tc.require: issueI9KDPI
 */
HWTEST_F(RSDisplayNodeTest, OnBoundsSizeChanged, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    displayNode->OnBoundsSizeChanged();
    EXPECT_NE(RSTransactionProxy::instance_, nullptr);
}

/**
 * @tc.name: SetDisplayOffset
 * @tc.desc: test results of SetDisplayOffset
 * @tc.type: FUNC
 * @tc.require: issueI9KDPI
 */
HWTEST_F(RSDisplayNodeTest, SetDisplayOffset, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    displayNode->SetDisplayOffset(0, 1);
    EXPECT_NE(RSTransactionProxy::instance_, nullptr);
}

/**
 * @tc.name: SetDisplayNodeMirrorConfig
 * @tc.desc: test results of SetDisplayNodeMirrorConfig
 * @tc.type: FUNC
 * @tc.require: issueI9KDPI
 */
HWTEST_F(RSDisplayNodeTest, SetDisplayNodeMirrorConfig, TestSize.Level1)
{
    RSDisplayNodeConfig displayNodeConfig;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(displayNodeConfig);
    displayNode->SetDisplayNodeMirrorConfig(displayNodeConfig);
    EXPECT_NE(RSTransactionProxy::instance_, nullptr);

    delete RSTransactionProxy::instance_;
    RSTransactionProxy::instance_ = nullptr;
    displayNode->SetDisplayNodeMirrorConfig(displayNodeConfig);
    ASSERT_TRUE(RSTransactionProxy::instance_ == nullptr);
    RSTransactionProxy::instance_ = new RSTransactionProxy();
}

/**
 * @tc.name: SetScreenRotation
 * @tc.desc: test results of SetScreenRotation
 * @tc.type: FUNC
 * @tc.require: issueI9KDPI
 */
HWTEST_F(RSDisplayNodeTest, SetScreenRotation, TestSize.Level1)
{
    RSDisplayNodeConfig displayNodeConfig;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(displayNodeConfig);
    uint32_t rotation = 0;
    displayNode->SetScreenRotation(rotation);

    rotation = 1;
    displayNode->SetScreenRotation(rotation);

    rotation = 2;
    displayNode->SetScreenRotation(rotation);

    rotation = 3;
    displayNode->SetScreenRotation(rotation);

    rotation = 4;
    displayNode->SetScreenRotation(rotation);
    EXPECT_NE(RSTransactionProxy::instance_, nullptr);

    delete RSTransactionProxy::instance_;
    RSTransactionProxy::instance_ = nullptr;
    displayNode->SetScreenRotation(rotation);
    ASSERT_TRUE(RSTransactionProxy::instance_ == nullptr);
    RSTransactionProxy::instance_ = new RSTransactionProxy();
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Unmarshalling Test
 * @tc.type: FUNC
 * @tc.require: issueI9N1QF
 */
HWTEST_F(RSDisplayNodeTest, UnmarshallingTest001, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);

    Parcel parcel;
    auto displayNodeTest1 = displayNode->Unmarshalling(parcel);
    EXPECT_EQ(displayNodeTest1, nullptr);

    uint32_t id = 100;
    uint32_t screenId = 0;
    bool isMirrored = true;
    parcel.WriteUint64(id);
    parcel.WriteUint64(screenId);
    parcel.WriteBool(isMirrored);
    auto displayNodeTest2 = displayNode->Unmarshalling(parcel);
    EXPECT_TRUE(displayNodeTest2 != nullptr);
    EXPECT_EQ(displayNodeTest2->GetId(), id);
    EXPECT_EQ(displayNodeTest2->IsMirrorDisplay(), isMirrored);
}

/**
 * @tc.name: SetScreenRotationTest003
 * @tc.desc: SetScreenRotation Test
 * @tc.type: FUNC
 * @tc.require: issueI9N1QF
 */
HWTEST_F(RSDisplayNodeTest, SetScreenRotationTest003, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);
    EXPECT_TRUE(displayNode != nullptr);
    displayNode->SetId(0);
    EXPECT_EQ(displayNode->GetId(), 0);
    displayNode->SetScreenRotation(0);
    displayNode->SetScreenRotation(1);
    displayNode->SetScreenRotation(2);
    displayNode->SetScreenRotation(3);
    displayNode->SetScreenRotation(4);
    EXPECT_NE(RSTransactionProxy::GetInstance(), nullptr);
}

/**
 * @tc.name: SetSecurityDisplay003
 * @tc.desc: SetScreenRotation Test
 * @tc.type: FUNC
 * @tc.require: issueI9R0EY
 */
HWTEST_F(RSDisplayNodeTest, SetSecurityDisplay003, TestSize.Level1)
{
    RSDisplayNodeConfig c;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(c);
    ASSERT_TRUE(displayNode != nullptr);
    displayNode->SetSecurityDisplay(false);
    EXPECT_FALSE(displayNode->GetSecurityDisplay());

    delete RSTransactionProxy::instance_;
    RSTransactionProxy::instance_ = nullptr;
    displayNode->SetSecurityDisplay(false);
    ASSERT_TRUE(RSTransactionProxy::instance_ == nullptr);
    RSTransactionProxy::instance_ = new RSTransactionProxy();
}

/**
 * @tc.name: ServiceControlBlockTree001
 * @tc.desc: AddDisplayNodeToTree RemoveDisplayNodeFromTree SetScbNodePid Test
 * @tc.type: FUNC
 * @tc.require: issueI9TI4Y
 */
HWTEST_F(RSDisplayNodeTest, ServiceControlBlockTree001, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);
    EXPECT_NE(displayNode, nullptr);

    // AddDisplayNodeToTree test
    displayNode->AddDisplayNodeToTree();
    // RemoveDisplayNodeFromTree test
    displayNode->RemoveDisplayNodeFromTree();
    // SetScbNodePid test
    std::vector<int32_t> oldScbPids;
    oldScbPids.emplace_back(0);
    displayNode->SetScbNodePid(oldScbPids, 0);
}

/**
 * @tc.name: SetScbNodePid
 * @tc.desc: SetScbNodePid test.
 * @tc.type: FUNC
 * @tc.require: issueI9UAON
 */
HWTEST_F(RSDisplayNodeTest, SetScbNodePid, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);
    EXPECT_TRUE(displayNode != nullptr);
    std::vector<int32_t> oldScbPids = {};
    int32_t currentScbPid = -1;
    displayNode->SetScbNodePid(oldScbPids, currentScbPid);
    oldScbPids.push_back(1);
    oldScbPids.push_back(2);
    displayNode->SetScbNodePid(oldScbPids, currentScbPid);
}

/**
 * @tc.name: SetVirtualScreenMuteStatus
 * @tc.desc: SetVirtualScreenMuteStatus test.
 * @tc.type: FUNC
 * @tc.require: issueIBTNC3
 */
HWTEST_F(RSDisplayNodeTest, SetVirtualScreenMuteStatus, TestSize.Level1)
{
    RSDisplayNodeConfig config;
    config.screenId = 6000;
    RSDisplayNode::SharedPtr displayNode = RSDisplayNode::Create(config);
    EXPECT_TRUE(displayNode != nullptr);

    displayNode->SetVirtualScreenMuteStatus(true);
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy != nullptr) {
        transactionProxy->FlushImplicitTransaction();
    }

    displayNode->SetVirtualScreenMuteStatus(false);
    if (transactionProxy != nullptr) {
        transactionProxy->FlushImplicitTransaction();
    }
}
} // namespace OHOS::Rosen