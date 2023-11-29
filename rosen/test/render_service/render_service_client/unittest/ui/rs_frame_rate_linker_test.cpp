/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "ui/rs_frame_rate_linker.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class RSFrameRateLinkerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSFrameRateLinkerTest::SetUpTestCase() {}
void RSFrameRateLinkerTest::TearDownTestCase() {}
void RSFrameRateLinkerTest::SetUp() {}
void RSFrameRateLinkerTest::TearDown() {}

/**
 * @tc.name: UpdateFrameRateRange
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSFrameRateLinkerTest, UpdateFrameRateRange, TestSize.Level1)
{
    RSFrameRateLinker rsFrameRateLinker;
    FrameRateRange range = {0, 0, 0};
    rsFrameRateLinker.UpdateFrameRateRange(range);

    rsFrameRateLinker.UpdateFrameRateRangeImme(range);
}

} // namespace Rosen
} // namespace OHOS