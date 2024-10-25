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
#include "command/rs_canvas_drawing_node_command.h"
#include "pipeline/rs_canvas_drawing_render_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSCanvasDrawingNodeCmdExtTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSCanvasDrawingNodeCmdExtTest::SetUpTestCase() {}
void RSCanvasDrawingNodeCmdExtTest::TearDownTestCase() {}
void RSCanvasDrawingNodeCmdExtTest::SetUp() {}
void RSCanvasDrawingNodeCmdExtTest::TearDown() {}
/**
 * @tc.name: CreateExtTest
 * @tc.desc: test.
 * @tc.type: FUNC
 */
HWTEST_F(RSCanvasDrawingNodeCmdExtTest, CreateExtTest, TestSize.Level1)
{
    RSContext context;
    int width = 1;
    int height = 1;
    NodeId targetId = static_cast<NodeId>(1);
    RSCanvasDrawingNodeCommandHelper::Create(context, targetId, false);

    RSCanvasDrawingNodeCommandHelper::ResetSurface(context, targetId, width, height);
    RSCanvasDrawingNodeCommandHelper::ResetSurface(context, 0, width, height);
}

} // namespace OHOS::Rosen
