/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "animation/rs_implicit_animator.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSImplicitAnimatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSImplicitAnimatorTest::SetUpTestCase() {}
void RSImplicitAnimatorTest::TearDownTestCase() {}
void RSImplicitAnimatorTest::SetUp() {}
void RSImplicitAnimatorTest::TearDown() {}

/**
 * @tc.name: OpenImplicitAnimation001
 * @tc.desc: Verify the OpenImplicitAnimation
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, GetBoundsTest, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest OpenImplicitAnimation001 start";
    RSAnimationTimingProtocol timingProtocol;
    float mass = 0.5f;
    float stiffness = 0.0f;
    float damping = 0.5f;
    float velocity = 1.0f;
    auto timingCurve = RSAnimationTimingCurve::CreateInterpolatingSpring(mass, stiffness, damping, velocity);
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();
    implicitAnimator->OpenImplicitAnimation(RSAnimationTimingProtocol::DEFAULT, timingCurve);
    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest OpenImplicitAnimation001 end";
}

/**
 * @tc.name: BeginImplicitDurationKeyFrameAnimation001
 * @tc.desc: Verify the BeginImplicitDurationKeyFrameAnimation
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, BeginImplicitDurationKeyFrameAnimation001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest BeginImplicitDurationKeyFrameAnimation001 start";
    int duration = 1000;
    RSAnimationTimingProtocol timingProtocol;
    float mass = 0.5f;
    float stiffness = 0.0f;
    float damping = 0.5f;
    float velocity = 1.0f;
    auto timingCurve = RSAnimationTimingCurve::CreateSpringCurve(velocity, mass, stiffness, damping);
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();
    implicitAnimator->BeginImplicitDurationKeyFrameAnimation(duration, timingCurve);

    implicitAnimator->OpenImplicitAnimation(RSAnimationTimingProtocol::DEFAULT, timingCurve);
    implicitAnimator->BeginImplicitDurationKeyFrameAnimation(duration, timingCurve);

    RSAnimationTimingProtocol timingProtocol1(0);
    auto timingCurve1 = RSAnimationTimingCurve::DEFAULT;
    implicitAnimator->OpenImplicitAnimation(timingProtocol1, timingCurve1);
    implicitAnimator->BeginImplicitDurationKeyFrameAnimation(duration, timingCurve1);

    implicitAnimator->OpenImplicitAnimation(timingProtocol, timingCurve1);
    implicitAnimator->BeginImplicitDurationKeyFrameAnimation(duration, timingCurve1);
    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest BeginImplicitDurationKeyFrameAnimation001 end";
}

/**
 * @tc.name: EndImplicitDurationKeyFrameAnimation001
 * @tc.desc: Verify the EndImplicitDurationKeyFrameAnimation
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, EndImplicitDurationKeyFrameAnimation001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest EndImplicitDurationKeyFrameAnimation001 start";
    int duration = 1000;
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();
    implicitAnimator->EndImplicitDurationKeyFrameAnimation();

    RSAnimationTimingProtocol timingProtocol;
    auto timingCurve = RSAnimationTimingCurve::DEFAULT;
    implicitAnimator->OpenImplicitAnimation(timingProtocol, timingCurve);
    implicitAnimator->BeginImplicitDurationKeyFrameAnimation(duration, timingCurve);
    implicitAnimator->EndImplicitDurationKeyFrameAnimation();
    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest EndImplicitDurationKeyFrameAnimation001 end";
}
} // namespace Rosen
} // namespace OHOS
