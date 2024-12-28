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

#include "ipc_callbacks/rs_surface_occlusion_change_callback_proxy.h"
#include "mock_iremoter_objects.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class RSSurfaceCallbackProxyOcclusionChangeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSurfaceCallbackProxyOcclusionChangeTest::SetUpTestCase() {}
void RSSurfaceCallbackProxyOcclusionChangeTest::TearDownTestCase() {}
void RSSurfaceCallbackProxyOcclusionChangeTest::SetUp() {}
void RSSurfaceCallbackProxyOcclusionChangeTest::TearDown() {}

/**
 * @tc.name: OnSurfaceOcclusionVisibleChanged001
 * @tc.desc: Verify the OnSurfaceOcclusionVisibleChanged
 * @tc.type:FUNC
 * @tc.require: issueIB2AHG
 */
HWTEST_F(RSSurfaceCallbackProxyOcclusionChangeTest, OnSurfaceOcclusionVisibleChanged001, TestSize.Level1)
{
    sptr<MockIRemoteObject> remoteMocker = new MockIRemoteObject();
    ASSERT_TRUE(remoteMocker != nullptr);
    auto rsSurfaceOcclusionChangeCallbackProxy = std::make_shared<RSSurfaceOcclusionChangeCallbackProxy>(remoteMocker);
    ASSERT_TRUE(rsSurfaceOcclusionChangeCallbackProxy != nullptr);
    rsSurfaceOcclusionChangeCallbackProxy->OnSurfaceOcclusionVisibleChanged(1.f);
    ASSERT_EQ(remoteMocker->receivedCode_,
        static_cast<uint32_t>(RSISurfaceOcclusionChangeCallbackInterfaceCode::ON_SURFACE_OCCLUSION_VISIBLE_CHANGED));
}

/**
 * @tc.name: OnSurfaceOcclusionVisibleChanged002
 * @tc.desc: Verify the OnSurfaceOcclusionVisibleChanged error case
 * @tc.type:FUNC
 * @tc.require: issueIB2AHG
 */
HWTEST_F(RSSurfaceCallbackProxyOcclusionChangeTest, OnSurfaceOcclusionVisibleChanged002, TestSize.Level1)
{
    sptr<MockIRemoteObject> remoteMocker = new MockIRemoteObject();
    ASSERT_TRUE(remoteMocker != nullptr);
    remoteMocker->sendRequestResult_ = 1;
    auto rsSurfaceOcclusionChangeCallbackProxy->OnSurfaceOcclusionVisibleChanged(1.f);
    ASSERT_EQ(remoteMocker->receivedCode_,
        static_cast<uint32_t>(RSISurfaceOcclusionChangeCallbackInterfaceCode::ON_SURFACE_OCCLUSION_VISIBLE_CHANGED));
    rsSurfaceOcclusionChangeCallbackProxy = std::make_shared<RSSurfaceOcclusionChangeCallbackProxy>(remoteMocker);
    ASSERT_TRUE(rsSurfaceOcclusionChangeCallbackProxy != nullptr);
}
} // namespace Rosen
} // namespace OHOS