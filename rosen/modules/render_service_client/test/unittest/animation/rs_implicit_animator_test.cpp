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
#include "animation/rs_implicit_animation_param.h"
#include "animation/rs_motion_path_option.h"
#include "ui/rs_canvas_node.h"
#include "modifier/rs_property_modifier.h"

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

    const std::string  ANIMATION_PATH = "L350 0 L150 100";
    const Vector4f ANIMATION_START_BOUNDS = Vector4f(100.f, 100.f, 200.f, 300.f);
    const Vector4f ANIMATION_END_BOUNDS = Vector4f(100.f, 100.f, 300.f, 300.f);
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

/**
 * @tc.name: EndImplicitPathAnimation001
 * @tc.desc: Verify the EndImplicitPathAnimation
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, EndImplicitPathAnimation001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest EndImplicitPathAnimation001 start";
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();
    implicitAnimator->EndImplicitPathAnimation();

    auto motionPathOption = std::make_shared<RSMotionPathOption>(ANIMATION_PATH);
    RSAnimationTimingProtocol timingProtocol;
    auto timingCurve = RSAnimationTimingCurve::DEFAULT;
    implicitAnimator->OpenImplicitAnimation(timingProtocol, timingCurve);
    implicitAnimator->BeginImplicitPathAnimation(motionPathOption);
    implicitAnimator->EndImplicitPathAnimation();
    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest EndImplicitPathAnimation001 end";
}

/**
 * @tc.name: CancelImplicitAnimation001
 * @tc.desc: Verify the CancelImplicitAnimation
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, CancelImplicitAnimation001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CancelImplicitAnimation001 start";

    std::shared_ptr<RSCanvasNode> canvasNode = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector2f>> property = nullptr;

    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();
    implicitAnimator->CancelImplicitAnimation(canvasNode, property);

    auto canvasNode1 = RSCanvasNode::Create();
    std::shared_ptr<RSAnimatableProperty<Vector2f>> property1 = nullptr;
    implicitAnimator->CancelImplicitAnimation(canvasNode1, property1);

    auto canvasNode2 = RSCanvasNode::Create();
    auto property2 = std::make_shared<RSAnimatableProperty<Vector2f>>(Vector2f(0.f, 0.f));
    implicitAnimator->CancelImplicitAnimation(canvasNode2, property2);

    auto property3 = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_START_BOUNDS);
    auto startProperty = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_START_BOUNDS);
    auto endProperty = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_END_BOUNDS);
    auto modifier3 = std::make_shared<RSBoundsModifier>(property3);
    auto canvasNode3 = RSCanvasNode::Create();
    canvasNode3->AddModifier(modifier3);

    auto timingCurve = RSAnimationTimingCurve::DEFAULT;
    RSAnimationTimingProtocol timingProtocol3;
    implicitAnimator->OpenImplicitAnimation(timingProtocol3, timingCurve);
    implicitAnimator->CreateImplicitAnimation(canvasNode3, property3, startProperty, endProperty);
    implicitAnimator->CancelImplicitAnimation(canvasNode3, property3);

    RSAnimationTimingProtocol timingProtocol4(0);
    implicitAnimator->OpenImplicitAnimation(timingProtocol4, timingCurve);
    implicitAnimator->CreateImplicitAnimation(canvasNode3, property3, startProperty, endProperty);
    implicitAnimator->CancelImplicitAnimation(canvasNode3, property3);

    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CancelImplicitAnimation001 end";
}

/**
 * @tc.name: CreateImplicitAnimationWithInitialVelocity001
 * @tc.desc: Verify the CreateImplicitAnimationWithInitialVelocity
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, CreateImplicitAnimationWithInitialVelocity001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CreateImplicitAnimationWithInitialVelocity001 start";
    RSAnimationTimingProtocol timingProtocol;
    auto timingCurve = RSAnimationTimingCurve::SPRING;
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();

    std::shared_ptr<RSCanvasNode> node = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector4f>> prop = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector4f>> prop_start = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector4f>> prop_end = nullptr;
    auto velocity = std::make_shared<RSAnimatableProperty<float>>(1.0f);

    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(node, prop, prop_start, prop_end, velocity);

    auto node1 = RSCanvasNode::Create();
    implicitAnimator->OpenImplicitAnimation(RSAnimationTimingProtocol::DEFAULT, RSAnimationTimingCurve::DEFAULT);
    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(node1, prop, prop_start, prop_end, velocity);

    auto prop1 = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_START_BOUNDS);
    implicitAnimator->OpenImplicitAnimation(RSAnimationTimingProtocol::DEFAULT, RSAnimationTimingCurve::DEFAULT);
    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(node1, prop1, prop_start, prop_end, velocity);

    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CreateImplicitAnimationWithInitialVelocity001 end";
}

/**
 * @tc.name: CreateImplicitAnimationWithInitialVelocity002
 * @tc.desc: Verify the CreateImplicitAnimationWithInitialVelocity
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, CreateImplicitAnimationWithInitialVelocity002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CreateImplicitAnimationWithInitialVelocity002 start";
    RSAnimationTimingProtocol timingProtocol;
    auto timingCurve = RSAnimationTimingCurve::SPRING;
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();

    auto canvasNode = RSCanvasNode::Create();
    auto property = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_START_BOUNDS);
    auto startProperty = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_START_BOUNDS);
    auto endProperty = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_END_BOUNDS);
    auto velocity = std::make_shared<RSAnimatableProperty<float>>(1.0f);
    auto modifier = std::make_shared<RSBoundsModifier>(property);
    canvasNode->AddModifier(modifier);

    implicitAnimator->OpenImplicitAnimation(RSAnimationTimingProtocol::DEFAULT, timingCurve);
    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(
        canvasNode, property, startProperty, endProperty, velocity);

    bool flag = false;
    std::function<void()> func = [&]() { flag = !flag; };
    auto finishCallback = std::make_shared<AnimationFinishCallback>(func);
    auto repeatCallback = std::make_shared<AnimationRepeatCallback>(func);

    implicitAnimator->OpenImplicitAnimation(
        RSAnimationTimingProtocol::DEFAULT, timingCurve, std::move(finishCallback), nullptr);
    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(
        canvasNode, property, startProperty, endProperty, velocity);

    implicitAnimator->OpenImplicitAnimation(
        RSAnimationTimingProtocol::DEFAULT, timingCurve, std::move(finishCallback), std::move(repeatCallback));
    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(
        canvasNode, property, startProperty, endProperty, velocity);

    auto finishCallBack = std::make_shared<AnimationFinishCallback>(nullptr);
    implicitAnimator->OpenImplicitAnimation(finishCallBack);
    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CreateImplicitAnimationWithInitialVelocity002 end";
}

/**
 * @tc.name: ProcessEmptyAnimationTest001
 * @tc.desc: Verify the ProcessEmptyAnimationTest001
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, ProcessEmptyAnimationTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest ProcessEmptyAnimationTest001 start";
    RSAnimationTimingProtocol timingProtocol;
    auto timingCurve = RSAnimationTimingCurve::SPRING;
    timingProtocol.duration_ = -1;
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();
    std::shared_ptr<AnimationFinishCallback> finishCallback = std::make_shared<AnimationFinishCallback>(nullptr);
    implicitAnimator->OpenImplicitAnimation(timingProtocol, timingCurve, std::move(finishCallback));
    EXPECT_TRUE(implicitAnimator != nullptr);

    finishCallback = std::make_shared<AnimationFinishCallback>(nullptr, FinishCallbackType::TIME_INSENSITIVE);
    implicitAnimator->ProcessEmptyAnimations(finishCallback);

    finishCallback = std::make_shared<AnimationFinishCallback>(nullptr, FinishCallbackType::TIME_INSENSITIVE);
    implicitAnimator->ProcessEmptyAnimations(finishCallback);

    auto implicitAnimator2 = std::make_shared<RSImplicitAnimator>();
    auto canvasNode = RSCanvasNode::Create();
    implicitAnimator2->CreateImplicitTransition(*canvasNode.get()); 
    finishCallback = std::make_shared<AnimationFinishCallback>(nullptr);
    implicitAnimator2->OpenImplicitAnimation(std::move(finishCallback));
    implicitAnimator2->ProcessEmptyAnimations(finishCallback);

    implicitAnimator2->interactiveImplicitAnimations_.push({});
    implicitAnimator2->CloseInterActiveImplicitAnimation(true);
    while (!implicitAnimator2->interactiveImplicitAnimations_.empty()) {
        implicitAnimator2->PopImplicitParam();
    }
    implicitAnimator2->CloseInterActiveImplicitAnimation(true);

    implicitAnimator2->BeginImplicitPathAnimation(nullptr);
    RSAnimationTimingProtocol timingProtocol3;
    auto timingCurve3 = RSAnimationTimingCurve();
    timingCurve3.type_ = RSAnimationTimingCurve::CurveType::SPRING;
    timingProtocol3.duration_ = 0;
    auto implicitAnimator3 = std::make_shared<RSImplicitAnimator>();
    finishCallback = std::make_shared<AnimationFinishCallback>();
    implicitAnimator3->OpenImplicitAnimation(timingProtocol3, timingCurve3, std::move(finishCallback));
    implicitAnimator3->BeginImplicitPathAnimation(nullptr);
    EXPECT_TRUE(implicitAnimator2 != nullptr);
    EXPECT_TRUE(implicitAnimator3 != nullptr);

    implicitAnimator2->BeginImplicitTransition(nullptr, false);

    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest ProcessEmptyAnimationTest001 end";
}

/**
 * @tc.name: CreateImplicitAnimationWithInitialVelocity003
 * @tc.desc: Verify the CreateImplicitAnimationWithInitialVelocity
 * @tc.type:FUNC
 */
HWTEST_F(RSImplicitAnimatorTest, CreateImplicitAnimationWithInitialVelocity003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CreateImplicitAnimationWithInitialVelocity003 start";
    RSAnimationTimingProtocol timingProtocol;
    auto timingCurve = RSAnimationTimingCurve::SPRING;
    auto implicitAnimator = std::make_shared<RSImplicitAnimator>();

    std::shared_ptr<RSCanvasNode> node = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector4f>> prop = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector4f>> prop_start = nullptr;
    std::shared_ptr<RSAnimatableProperty<Vector4f>> prop_end = nullptr;
    auto velocity = std::make_shared<RSAnimatableProperty<float>>(1.0f);

    std::shared_ptr <RSImplicitSpringAnimationParam> para =
        std::make_shared<RSImplicitSpringAnimationParam>(timingProtocol, timingCurve);
    implicitAnimator->implicitAnimationParams_.push(para);

    auto node1 = RSCanvasNode::Create();
    implicitAnimator->OpenImplicitAnimation(RSAnimationTimingProtocol::DEFAULT, RSAnimationTimingCurve::DEFAULT);

    auto prop1 = std::make_shared<RSAnimatableProperty<Vector4f>>(ANIMATION_START_BOUNDS);
    timingProtocol.duration_ = -1;
    std::shared_ptr<AnimationFinishCallback> finishCallback =
        std::make_shared<AnimationFinishCallback>(nullptr, FinishCallbackType::LOGICALLY);

    implicitAnimator->OpenImplicitAnimation(timingProtocol, RSAnimationTimingCurve::DEFAULT, std::move(finishCallback));
    implicitAnimator->CreateImplicitAnimationWithInitialVelocity(node1, prop1, prop_start, prop_end, velocity);
    prop1->id_ = 0;
    implicitAnimator->CreateImplicitAnimation(node1, prop1, prop_start, prop_end);

    timingProtocol.duration_ = 1;
    para = std::make_shared<RSImplicitCancelAnimationParam>(timingProtocol, timingCurve);
    implicitAnimator->OpenImplicitAnimation(timingProtocol, RSAnimationTimingCurve::DEFAULT, std::move(finishCallback));
    implicitAnimator->implicitAnimationParams_.push(para);
    implicitAnimator->CreateImplicitAnimation(node1, prop1, prop_start, prop_end);

    prop1->id_ = 1;
    auto repeatCallBack = std::make_shared<AnimationRepeatCallback>(nullptr);
    implicitAnimator->OpenImplicitAnimation(
        timingProtocol, RSAnimationTimingCurve::DEFAULT, std::move(finishCallback), std::move(repeatCallBack));
    para = std::make_shared<RSImplicitSpringAnimationParam>(timingProtocol, timingCurve);
    implicitAnimator->implicitAnimationParams_.push(para);
    implicitAnimator->CreateImplicitAnimation(node1, prop1, prop_start, prop_end);

    para = std::make_shared<RSImplicitInterpolatingSpringAnimationParam>(timingProtocol, timingCurve);
    implicitAnimator->implicitAnimationParams_.push(para);
    implicitAnimator->CreateImplicitAnimation(node1, prop1, prop_start, prop_end);

    auto pathOpt = std::make_shared<RSMotionPathOption>("");
    para = std::make_shared<RSImplicitPathAnimationParam>(timingProtocol, timingCurve, pathOpt);
    implicitAnimator->implicitAnimationParams_.push(para);
    implicitAnimator->CreateImplicitAnimation(node1, prop1, prop_start, prop_end);

    prop1->isCustom_ = true;
    para = std::make_shared<RSImplicitAnimationParam>(timingProtocol, Rosen::ImplicitAnimationParamType::INVALID);
    implicitAnimator->implicitAnimationParams_.push(para);
    implicitAnimator->CreateImplicitAnimation(node1, prop1, prop_start, prop_end);

    implicitAnimator->ExecuteWithoutAnimation(nullptr);

    EXPECT_TRUE(implicitAnimator != nullptr);
    GTEST_LOG_(INFO) << "RSImplicitAnimatorTest CreateImplicitAnimationWithInitialVelocity003 end";
}
} // namespace Rosen
} // namespace OHOS
