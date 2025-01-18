/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "feature/anco_manager/rs_ext_node_operation.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSExtNodeOperationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: GetInstance001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSExtNodeOperationTest, GetInstance001, TestSize.Level1)
{
    auto& rs = RSExtNodeOperation::GetInstance();
    (void)(rs);
    ASSERT_FALSE(RSExtNodeOperation::GetInstance().CheckNeedToProcess("test"));
}

/**
 * @tc.name: CheckNeedToProcess001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSExtNodeOperationTest, CheckNeedToProcess001, TestSize.Level1)
{
    bool ret = RSExtNodeOperation::GetInstance().CheckNeedToProcess("test_id");
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ProcessRSSurfaceNode001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSExtNodeOperationTest, ProcessRSSurfaceNode001, TestSize.Level1)
{
    RSExtNodeOperation::GetInstance().ProcessRSExtNode("test_id", 0x5555, 1.0f, 1.0f, nullptr);
    ASSERT_FALSE(RSExtNodeOperation::GetInstance().CheckNeedToProcess("test_id"));
}
} // namespace OHOS::Rosen
