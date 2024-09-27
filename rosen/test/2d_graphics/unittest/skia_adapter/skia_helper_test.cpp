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

#include <cstddef>
#include "gtest/gtest.h"
#include "skia_adapter/skia_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class SkiaHelperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SkiaHelperTest::SetUpTestCase() {}
void SkiaHelperTest::TearDownTestCase() {}
void SkiaHelperTest::SetUp() {}
void SkiaHelperTest::TearDown() {}

/**
 * @tc.name: SkiaHelper001
 * @tc.desc: Test SkiaHelper
 * @tc.type: FUNC
 * @tc.require: I8VQSW
 */
HWTEST_F(SkiaHelperTest, SkiaHelper001, TestSize.Level1)
{
    std::shared_ptr<SkiaHelper> skiaHelper = std::make_shared<SkiaHelper>();
    ASSERT_TRUE(skiaHelper->FlattenableSerialize(nullptr) == nullptr);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS