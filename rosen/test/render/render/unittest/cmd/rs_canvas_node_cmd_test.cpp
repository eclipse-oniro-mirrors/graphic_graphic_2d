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
#include "include/command/rs_canvas_node_command.h"
#include "pipeline/rs_canvas_render_node.h"
#include "pipeline/rs_render_node_gc.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSCanvasNodeCmdExtTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSCanvasNodeCmdExtTest::SetUpTestCase() {}
void RSCanvasNodeCmdExtTest::TearDownTestCase() {}
void RSCanvasNodeCmdExtTest::SetUp() {}
void RSCanvasNodeCmdExtTest::TearDown() {}

/**
 * @tc.name: CreateExtTest001
 * @tc.desc: Create test.
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasNodeCmdExtTest, CreateExtTest001, TestSize.Level1)
{
    RSContext context;
    NodeId targetId = static_cast<NodeId>(-1);
    RSCanvasNodeCommandHelper::Create(context, targetId, false);
}

/**
 * @tc.name: Create002
 * @tc.desc: test results of Create
 * @tc.type: FUNC
 * @tc.require: issueI9P2KH
 */
HWTEST_F(RSCanvasNodeCmdExtTest, CreateExtTest002, TestSize.Level1)
{
    RSContext context;
    NodeId targetId = 0;
    RSCanvasNodeCommandHelper::Create(context, targetId, false);
}

/**
 * @tc.name: TestRSCanvasNodeCmdExtTest001
 * @tc.desc: UpdateRecording test.
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasNodeCmdExtTest, TestRSCanvasNodeCmdExtTest001, TestSize.Level1)
{
    RSContext context;
    NodeId nodeId = static_cast<NodeId>(-1);
    std::shared_ptr<Drawing::DrawCmdList> drawCmds = nullptr;
    RSModifierType type = RSModifierType::INVALID;
    RSCanvasNodeCommandHelper::UpdateRecording(context, nodeId, drawCmds, static_cast<uint16_t>(type));
}

/**
 * @tc.name: TestRSCanvasNodeCmdExtTest002
 * @tc.desc: ClearRecording test.
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasNodeCmdExtTest, TestRSCanvasNodeCmdExtTest002, TestSize.Level1)
{
    RSContext context;
    NodeId nodeId = static_cast<NodeId>(-1);
    RSCanvasNodeCommandHelper::ClearRecording(context, nodeId);
    ASSERT_EQ(context.GetNodeMap().GetRenderNode<RSCanvasRenderNode>(nodeId), nullptr);
}

/**
 * @tc.name: ClearRecordingExtTest001
 * @tc.desc: test results of ClearRecording
 * @tc.type: FUNC
 * @tc.require: issueI9P2KH
 */
HWTEST_F(RSCanvasNodeCmdExtTest, ClearRecordingExtTest001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSCanvasNodeCommandHelper::Create(context, id, true);
    RSCanvasNodeCommandHelper::ClearRecording(context, id);

    RSCanvasNodeCommandHelper::ClearRecording(context, 0);
    EXPECT_TRUE(id);
}

/**
 * @tc.name: UpdateRecordingExtTest001
 * @tc.desc: test results of UpdateRecording
 * @tc.type: FUNC
 * @tc.require: issueI9P2KH
 */
HWTEST_F(RSCanvasNodeCmdExtTest, UpdateRecordingExtTest001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSCanvasNodeCommandHelper::Create(context, id, true);
    std::shared_ptr<Drawing::DrawCmdList> drawCmds = nullptr;
    uint16_t modifierType = 1;
    RSCanvasNodeCommandHelper::UpdateRecording(context, id, drawCmds, modifierType);
    EXPECT_TRUE(drawCmds == nullptr);

    RSCanvasNodeCommandHelper::UpdateRecording(context, 0, drawCmds, modifierType);
    EXPECT_TRUE(drawCmds == nullptr);

    drawCmds = std::make_shared<Drawing::DrawCmdList>();
    RSCanvasNodeCommandHelper::UpdateRecording(context, id, drawCmds, modifierType);
    EXPECT_TRUE(drawCmds != nullptr);
}

/**
 * @tc.name: AddCmdToSingleFrameComposerExtTest001
 * @tc.desc: test results of AddCmdToSingleFrameComposer
 * @tc.type: FUNC
 * @tc.require: issueI9P2KH
 */
HWTEST_F(RSCanvasNodeCmdExtTest, AddCmdToSingleFrameComposerExtTest001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSCanvasNodeCommandHelper::Create(context, id, true);
    auto node = context.GetNodeMap().GetRenderNode<RSCanvasRenderNode>(id);
    std::shared_ptr<Drawing::DrawCmdList> drawCmds;
    RSModifierType type = RSModifierType::INVALID;
    bool res = RSCanvasNodeCommandHelper::AddCmdToSingleFrameComposer(node, drawCmds, type);
    EXPECT_TRUE(res == false);

    std::thread::id thisThreadId = std::this_thread::get_id();
    RSSingleFrameComposer::SetSingleFrameFlag(thisThreadId);
    res = RSCanvasNodeCommandHelper::AddCmdToSingleFrameComposer(node, drawCmds, type);
    EXPECT_TRUE(res);

    node->isNodeSingleFrameComposer_ = true;
    res = RSCanvasNodeCommandHelper::AddCmdToSingleFrameComposer(node, drawCmds, type);
    EXPECT_TRUE(res == false);

    std::thread::id threadId = std::this_thread::get_id();
    RSSingleFrameComposer::SetSingleFrameFlag(threadId);
    res = RSCanvasNodeCommandHelper::AddCmdToSingleFrameComposer(node, drawCmds, type);
    EXPECT_TRUE(res == false);
}
} // namespace OHOS::Rosen