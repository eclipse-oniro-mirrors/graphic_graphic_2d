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

#include <cstdlib>
#include <cstring>
#include <memory>
#include <securec.h>

#include "gtest/gtest.h"
#include "gtest/hwext/gtest-tag.h"
#include "message_parcel.h"

#include "modifier_ng/foreground/rs_env_foreground_color_render_modifier.h"
#include "property/rs_properties.h"
#include "pipeline/rs_canvas_render_node.h"

using namespace testing;

using namespace testing::ext;
using namespace OHOS::Rosen::ModifierNG;

namespace OHOS::Rosen {
class RSEnvForegroundColorRenderModifierNGTypeTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: RSEnvForegroundColorRenderModifierTest
 * @tc.desc: Apply & GetType
 * @tc.type: FUNC
 */
HWTEST_F(RSEnvForegroundColorRenderModifierNGTypeTest,
         RSEnvForegroundColorRenderModifierTest,
         TestSize.Level1)
{
    ModifierNG::RSEnvForegroundColorRenderModifier modifier;
    RSProperties properties;
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    modifier.Apply(&filterCanvas, properties);
    EXPECT_EQ(modifier.GetType(), ModifierNG::RSModifierType::ENV_FOREGROUND_COLOR);
}

/**
 * @tc.name: OnSetDirtyTest
 * @tc.desc: Test the function OnSetDirty
 * @tc.type: FUNC
 */
HWTEST_F(RSEnvForegroundColorRenderModifierNGTypeTest, OnSetDirtyTest, TestSize.Level1)
{
    ModifierNG::RSEnvForegroundColorRenderModifier modifier;
    modifier.OnSetDirty();
    EXPECT_EQ(modifier.target_.lock(), nullptr);
    
    NodeId nodeId = 1;
    std::shared_ptr<RSRenderNode> nodePtr = std::make_shared<RSCanvasRenderNode>(nodeId);
    std::weak_ptr<RSRenderNode> weakPtr = nodePtr;
    modifier->target_ = weakPtr;
    modifier.OnSetDirty();
    EXPECT_NE(modifier.target_.lock(), nullptr);
}
} // namespace OHOS::Rosen