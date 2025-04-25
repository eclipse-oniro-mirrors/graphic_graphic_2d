/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "command/rs_canvas_node_command.h"
#include "command/rs_node_command.h"
#include "command/rs_root_node_command.h"
#include "modifier_render_thread/rs_modifiers_draw_thread.h"
#include "render_context/shader_cache.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSModifiersDrawThreadTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSModifiersDrawThreadTest::SetUpTestCase() {}
void RSModifiersDrawThreadTest::TearDownTestCase() {}
void RSModifiersDrawThreadTest::SetUp() {}
void RSModifiersDrawThreadTest::TearDown() {}

/**
 * @tc.name: GetInstanceTest001
 * @tc.desc: test results of Instance
 * @tc.type: FUNC
 * @tc.require: issueIBWDR2
 */
HWTEST_F(RSModifiersDrawThreadTest, GetInstanceTest001, TestSize.Level1)
{
    ASSERT_EQ(&RSModifiersDrawThread::Instance(), &RSModifiersDrawThread::Instance());
}

/**
 * @tc.name: SetCacheDir001
 * @tc.desc: test results of SetCacheDir
 * @tc.type: FUNC
 * @tc.require: issueIBWDR2
 */
HWTEST_F(RSModifiersDrawThreadTest, SetCacheDir001, TestSize.Level1)
{
    const std::string shaderCacheDir_ = "/path/shadercachedir";
    RSModifiersDrawThread::Instance().SetCacheDir(shaderCacheDir_);
    ASSERT_NE(ShaderCache::Instance().filePath_.find(shaderCacheDir_), std::string::npos);
}

/**
 * @tc.name: Start001
 * @tc.desc: test results of Start
 * @tc.type: FUNC
 * @tc.require: issueIBWDR2
 */
HWTEST_F(RSModifiersDrawThreadTest, Start001, TestSize.Level1)
{
    RSModifiersDrawThread::Instance().Start();
    ASSERT_TRUE(RSModifiersDrawThread::Instance().isStarted_);
    RSModifiersDrawThread::Instance().Start();
    ASSERT_TRUE(RSModifiersDrawThread::Instance().isStarted_);
    ASSERT_NE(nullptr, RSModifiersDrawThread::Instance().runner_);
}

/**
 * @tc.name: PostTask001
 * @tc.desc: test results of PostTask
 * @tc.type: FUNC
 * @tc.require: issueIBWDR2
 */
HWTEST_F(RSModifiersDrawThreadTest, PostTask001, TestSize.Level1)
{
    RSModifiersDrawThread::Instance().PostTask([]() {});
    ASSERT_EQ(RSModifiersDrawThread::Instance().isStarted_, true);
}

/**
 * @tc.name: PostTask002
 * @tc.desc: test results of PostTask
 * @tc.type: FUNC
 * @tc.require: issueIBWDR2
 */
HWTEST_F(RSModifiersDrawThreadTest, PostTask002, TestSize.Level1)
{
    RSModifiersDrawThread::Instance().Start();
    RSModifiersDrawThread::Instance().PostTask([]() {});
    ASSERT_NE(RSModifiersDrawThread::Instance().handler_, nullptr);
}

/**
 * @tc.name: ScheduleTask001
 * @tc.desc: test results of ScheduleTask
 * @tc.type: FUNC
 * @tc.require: issueIBWDR2
 */
HWTEST_F(RSModifiersDrawThreadTest, ScheduleTask001, TestSize.Level1)
{
    auto task = []() {};  /* some task */
    auto future = RSModifiersDrawThread::Instance().ScheduleTask(task);
    ASSERT_EQ(future.valid(), true);
}

/**
 * @tc.name: TargetCommand001
 * @tc.desc: test results of TargetCommand as (type,subtype) is (rsnode,updatexxx)
 * @tc.type: FUNC
 * @tc.require: issueIC1FSX
 */
HWTEST_F(RSModifiersDrawThreadTest, TargetCommand001, TestSize.Level1)
{
    NodeId nodeId = 1;
    auto cmdList = std::make_shared<Drawing::DrawCmdList>();
    cmdList->SetHybridRenderType(Drawing::DrawCmdList::HybridRenderType::CANVAS);
    uint64_t propertyId = 1;
    auto cType = PropertyUpdateType::UPDATE_TYPE_OVERWRITE;
    auto cmd = std::make_unique<RSUpdatePropertyDrawCmdList>(nodeId, cmdList, propertyId, cType);
    ASSERT_TRUE(RSModifiersDrawThread::TargetCommand(Drawing::DrawCmdList::HybridRenderType::SVG, cmd->GetType(),
        cmd->GetSubType(), false));
}

/**
 * @tc.name: TargetCommand002
 * @tc.desc: test results of TargetCommand invalid
 * @tc.type: FUNC
 * @tc.require: issueIC1FSX
 */
HWTEST_F(RSModifiersDrawThreadTest, TargetCommand002, TestSize.Level1)
{
    NodeId nodeId = 1;
    auto cmdList = std::make_shared<Drawing::DrawCmdList>();
    cmdList->SetHybridRenderType(Drawing::DrawCmdList::HybridRenderType::NONE);
    uint64_t propertyId = 1;
    auto cType = PropertyUpdateType::UPDATE_TYPE_INCREMENTAL;
    auto cmd = std::make_unique<RSUpdatePropertyDrawCmdList>(nodeId, cmdList, propertyId, cType);
    ASSERT_FALSE(RSModifiersDrawThread::TargetCommand(Drawing::DrawCmdList::HybridRenderType::NONE, cmd->GetType(),
        cmd->GetSubType(), false));
    ASSERT_FALSE(RSModifiersDrawThread::TargetCommand(Drawing::DrawCmdList::HybridRenderType::NONE, cmd->GetType(),
        cmd->GetSubType(), true));
}

/**
 * @tc.name: ConvertTransactionTest001
 * @tc.desc: test results of ConvertTransaction of canvas drawing node
 * @tc.type: FUNC
 * @tc.require: issueIC1FSX
 */
HWTEST_F(RSModifiersDrawThreadTest, ConvertTransactionTest001, TestSize.Level1)
{
    NodeId nodeId = 1;
    auto mType = RSModifierType::CONTENT_STYLE;
    auto cmdList = std::make_shared<Drawing::DrawCmdList>();
    cmdList->SetHybridRenderType(Drawing::DrawCmdList::HybridRenderType::CANVAS);
    auto cmd = std::make_unique<RSCanvasNodeUpdateRecording>(nodeId, cmdList, static_cast<uint16_t>(mType));
    auto transactionData = std::make_unique<RSTransactionData>();
    transactionData->AddCommand(std::move(cmd), nodeId, FollowType::NONE);
    RSModifiersDrawThread::ConvertTransaction(transactionData);
    ASSERT_NE(transactionData, nullptr);
}

/**
 * @tc.name: ConvertTransactionTest002
 * @tc.desc: test results of ConvertTransaction of text
 * @tc.type: FUNC
 * @tc.require: issueIC1FSX
 */
HWTEST_F(RSModifiersDrawThreadTest, ConvertTransactionTest002, TestSize.Level1)
{
    NodeId nodeId = 1;
    auto mType = RSModifierType::CONTENT_STYLE;
    auto cmdList = std::make_shared<Drawing::DrawCmdList>();
    cmdList->SetHybridRenderType(Drawing::DrawCmdList::HybridRenderType::TEXT);
    auto cmd = std::make_unique<RSCanvasNodeUpdateRecording>(nodeId, cmdList, static_cast<uint16_t>(mType));
    auto transactionData = std::make_unique<RSTransactionData>();
    transactionData->AddCommand(std::move(cmd), nodeId, FollowType::NONE);
    RSModifiersDrawThread::ConvertTransaction(transactionData);
    ASSERT_NE(transactionData, nullptr);
}
} // namespace OHOS::Rosen