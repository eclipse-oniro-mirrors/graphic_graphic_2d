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

#include "gtest/gtest.h"
#include "gtest/hwext/gtest-tag.h"

#include "command_modifier/rs_canvas_drawing_node_command_modifier.h"
#include "ui/rs_canvas_drawing_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class RSCanvasDrawingNodeCommandModifierTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSCanvasDrawingNodeCommandModifierTest::SetUpTestCase() {}
void RSCanvasDrawingNodeCommandModifierTest::TearDownTestCase() {}
void RSCanvasDrawingNodeCommandModifierTest::SetUp() {}
void RSCanvasDrawingNodeCommandModifierTest::TearDown() {}

/**
 * @tc.name: ResetSurfaceTest001
 * @tc.desc: Test GetType, SetParam same/different, GetParam, DumpParam
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasDrawingNodeCommandModifierTest, ResetSurfaceTest001, TestSize.Level1)
{
    auto node = RSCanvasDrawingNode::Create();
    ResetSurfaceCmdParam param{100, 200, 1};
    auto mod = std::make_shared<ResetSurfaceCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::RESET_SURFACE);
    EXPECT_EQ(mod->GetParam().width_, 100);
    EXPECT_EQ(mod->GetParam().height_, 200);
    EXPECT_EQ(mod->GetParam().resetSurfaceIndex_, 1);

    bool ret = mod->SetParam(param);
    EXPECT_TRUE(ret);

    ResetSurfaceCmdParam param2{300, 400, 2};
    ret = mod->SetParam(param2);
    EXPECT_TRUE(ret);
    EXPECT_EQ(mod->GetParam().width_, 300);
    EXPECT_EQ(mod->GetParam().height_, 400);
    EXPECT_EQ(mod->GetParam().resetSurfaceIndex_, 2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("width"), std::string::npos);
    EXPECT_NE(out.find("height"), std::string::npos);
    EXPECT_NE(out.find("resetSurfaceIndex"), std::string::npos);
}

/**
 * @tc.name: ResetSurfaceTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasDrawingNodeCommandModifierTest, ResetSurfaceTest002, TestSize.Level1)
{
    std::weak_ptr<RSNode> weakNode;
    { auto n = RSCanvasDrawingNode::Create(); weakNode = n; }
    ResetSurfaceCmdParam param{0, 0, 0};
    auto mod = std::make_shared<ResetSurfaceCmdModifier>(weakNode, param);
    mod->UpdateToRender();
}

/**
 * @tc.name: ResetSurfaceTest003
 * @tc.desc: Test UpdateToRenderWithResult with null node returns false
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasDrawingNodeCommandModifierTest, ResetSurfaceTest003, TestSize.Level1)
{
    std::weak_ptr<RSNode> weakNode;
    { auto n = RSCanvasDrawingNode::Create(); weakNode = n; }
    ResetSurfaceCmdParam param{0, 0, 0};
    auto mod = std::make_shared<ResetSurfaceCmdModifier>(weakNode, param);
    auto result = mod->UpdateToRenderWithResult();
    bool val = std::get<bool>(result);
    EXPECT_FALSE(val);
}

/**
 * @tc.name: ResetSurfaceTest004
 * @tc.desc: Test UpdateToRenderWithResult with valid node
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasDrawingNodeCommandModifierTest, ResetSurfaceTest004, TestSize.Level1)
{
    auto node = RSCanvasDrawingNode::Create();
    ResetSurfaceCmdParam param{100, 200, 0};
    auto mod = std::make_shared<ResetSurfaceCmdModifier>(node, param);
    auto result = mod->UpdateToRenderWithResult();
    bool val = std::get<bool>(result);
    EXPECT_TRUE(val);
}

/**
 * @tc.name: ResetSurfaceTest005
 * @tc.desc: Test UpdateToRender with valid node
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasDrawingNodeCommandModifierTest, ResetSurfaceTest005, TestSize.Level1)
{
    auto node = RSCanvasDrawingNode::Create();
    ResetSurfaceCmdParam param{50, 60, 3};
    auto mod = std::make_shared<ResetSurfaceCmdModifier>(node, param);
    mod->UpdateToRender();
}

} // namespace Rosen
} // namespace OHOS
