/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <gtest/gtest.h>

#include "screen_manager/rs_screen_props.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSRenderScreenPropsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderScreenPropsTest::SetUpTestCase() {}
void RSRenderScreenPropsTest::TearDownTestCase() {}
void RSRenderScreenPropsTest::SetUp() {}
void RSRenderScreenPropsTest::TearDown() {}

/**
 * @tc.name: Marshalling001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderScreenPropsTest, Marshalling001, TestSize.Level1)
{
    RSScreenProps screenProps;
    Parcel parcel;
    ASSERT_TRUE(screenProps.Marshalling(parcel));
}

/**
 * @tc.name: Unmarshalling001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderScreenPropsTest, Unmarshalling001, TestSize.Level1)
{
    RSScreenProps screenProps;
    Parcel parcel;
    ASSERT_TRUE(screenProps.Unmarshalling(parcel));
}

/**
 * @tc.name: marshallingAndUnmarshallling001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderScreenPropsTest, marshallingAndUnmarshallling001, TestSize.Level1)
{
    RSScreenProps screenProps("11", 1, 1);
    Parcel parcel;
    char* buffer = static_cast<char *>(malloc(parcel.GetMaxCapacity()));
    auto bufferSize = parcel.GetMaxCapacity();
    memset_s(buffer, parcel.GetMaxCapacity(), 0, parcel.GetMaxCapacity());
    ASSERT_TRUE(parcel.WriteUnpadBuffer(buffer, parcel.GetMaxCapacity()));
    bool ret = false;
    parcel.SkipBytes(bufferSize);
    while (!ret) {
        size_t position = parcel.GetWritePosition();
        ret = screenProps.Marshalling(parcel) &&
              (std::shared_ptr<RSScreenProps>(RSScreenProps::Unmarshalling(parcel)) != nullptr);
        parcel.SetMaxCapacity(parcel.GetMaxCapacity() + 1);
        if (!ret) {
            parcel.RewindWrite(position);
            parcel.RewindRead(bufferSize);
        }
    }
    free(buffer);
    ASSERT_TRUE(ret);
}
} // namespace Rosen
} // namespace OHOS
