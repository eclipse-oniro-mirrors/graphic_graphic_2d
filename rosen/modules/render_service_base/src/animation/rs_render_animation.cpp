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

#include "animation/rs_render_animation.h"

#include "command/rs_animation_command.h"
#include "common/rs_optional_trace.h"
#include "pipeline/rs_canvas_render_node.h"
#include "command/rs_message_processor.h"
#include "platform/common/rs_log.h"
#include "rs_profiler.h"

namespace OHOS {
namespace Rosen {
RSRenderAnimation::RSRenderAnimation(AnimationId id) : id_(id) {}

void RSRenderAnimation::DumpAnimation(std::string& out) const
{
    out += "Animation: [id:" + std::to_string(id_) + ", ";
    DumpAnimationInfo(out);
    out += ", AnimationState:" + std::to_string(static_cast<int>(state_));
    if (!targetName_.empty()) {
        out += ", NodeName:" + targetName_;
    }
    out += ", Duration:" + std::to_string(animationFraction_.GetDuration());
    out += ", StartDelay:" + std::to_string(animationFraction_.GetStartDelay());
    out += ", Speed:" + std::to_string(animationFraction_.GetSpeed());
    out += ", RepeatCount:" + std::to_string(animationFraction_.GetRepeatCount());
    out += ", AutoReverse:" + std::to_string(animationFraction_.GetAutoReverse());
    out += ", Direction:" + std::to_string(animationFraction_.GetDirection());
    out += ", FillMode:" + std::to_string(static_cast<int>(animationFraction_.GetFillMode()));
    out += ", RepeatCallbackEnable:" + std::to_string(animationFraction_.GetRepeatCallbackEnable());
    out += ", FrameRateRange_min:" + std::to_string(animationFraction_.GetFrameRateRange().min_);
    out += ", FrameRateRange_max:" + std::to_string(animationFraction_.GetFrameRateRange().max_);
    out += ", FrameRateRange_prefered:" + std::to_string(animationFraction_.GetFrameRateRange().preferred_);
    out += ", FrameRateRange_componentScene:" + animationFraction_.GetFrameRateRange().GetComponentName();
    out += ", Token:" + std::to_string(token_);
    out += "]";
}

void RSRenderAnimation::DumpAnimationInfo(std::string& out) const
{
    out += "Type:Unknown";
}

AnimationId RSRenderAnimation::GetAnimationId() const
{
    return id_;
}

bool RSRenderAnimation::IsStarted() const
{
    return state_ != AnimationState::INITIALIZED;
}

bool RSRenderAnimation::IsRunning() const
{
    return state_ == AnimationState::RUNNING;
}

bool RSRenderAnimation::IsPaused() const
{
    return state_ == AnimationState::PAUSED;
}

bool RSRenderAnimation::IsFinished() const
{
    return state_ == AnimationState::FINISHED;
}

PropertyId RSRenderAnimation::GetPropertyId() const
{
    return 0;
}

void RSRenderAnimation::Attach(RSRenderNode* renderNode)
{
    if (target_ != nullptr) {
        Detach();
    }
    target_ = renderNode;
    if (target_ != nullptr) {
        targetId_ = target_->GetId();
        targetName_ = target_->GetNodeName();
        target_->CheckGroupableAnimation(GetPropertyId(), true);
    }
    OnAttach();
    Start();
    needUpdateStartTime_ = false;
}

void RSRenderAnimation::Detach(bool forceDetach)
{
    if (!forceDetach) {
        OnDetach();
        if (target_ != nullptr) {
            target_->CheckGroupableAnimation(GetPropertyId(), false);
        }
    }
    target_ = nullptr;
}

NodeId RSRenderAnimation::GetTargetId() const
{
    return targetId_;
}

const std::string RSRenderAnimation::GetTargetName() const
{
    return targetName_;
}

void RSRenderAnimation::Start()
{
    if (IsStarted()) {
        ROSEN_LOGE("Failed to start animation, animation has started!");
        return;
    }

    state_ = AnimationState::RUNNING;
    needUpdateStartTime_ = true;
    ProcessFillModeOnStart(animationFraction_.GetStartFraction());
}

void RSRenderAnimation::Finish()
{
    RS_LOGI_LIMIT("Animation[%{public}" PRIu64 "] received finish", id_);
    if (!IsPaused() && !IsRunning()) {
        ROSEN_LOGD("Failed to finish animation, animation is not running!");
        return;
    }

    state_ = AnimationState::FINISHED;
    ProcessFillModeOnFinish(animationFraction_.GetEndFraction());
}

void RSRenderAnimation::FinishOnPosition(RSInteractiveAnimationPosition pos)
{
    if (!IsPaused() && !IsRunning()) {
        ROSEN_LOGD("Failed to finish animation, animation is not running!");
        return;
    }

    state_ = AnimationState::FINISHED;

    if (pos == RSInteractiveAnimationPosition::START) {
        ProcessFillModeOnFinish(animationFraction_.GetStartFraction());
    } else if (pos == RSInteractiveAnimationPosition::END) {
        ProcessFillModeOnFinish(animationFraction_.GetEndFraction());
    }
}

void RSRenderAnimation::FinishOnCurrentPosition()
{
    if (!IsPaused() && !IsRunning()) {
        ROSEN_LOGD("Failed to finish animation, animation is not running!");
        return;
    }

    state_ = AnimationState::FINISHED;
}

void RSRenderAnimation::Pause()
{
    RS_LOGI_LIMIT("Animation[%{public}" PRIu64 "] received pause", id_);
    if (!IsRunning()) {
        ROSEN_LOGE("Failed to pause animation, animation is not running!");
        return;
    }

    state_ = AnimationState::PAUSED;
}

void RSRenderAnimation::Resume()
{
    RS_LOGI_LIMIT("Animation[%{public}" PRIu64 "] received resume", id_);
    if (!IsPaused()) {
        ROSEN_LOGE("Failed to resume animation, animation is not paused!");
        return;
    }

    state_ = AnimationState::RUNNING;
    needUpdateStartTime_ = true;

    UpdateFractionAfterContinue();
}

void RSRenderAnimation::SetFraction(float fraction)
{
    if (!IsPaused()) {
        ROSEN_LOGE("Failed to set fraction, animation is not paused!");
        return;
    }

    fraction = std::min(std::max(fraction, 0.0f), 1.0f);
    OnSetFraction(fraction);
}

void RSRenderAnimation::SetReversedAndContinue()
{
    if (!IsPaused()) {
        ROSEN_LOGE("Failed to reverse animation, animation is not running!");
        return;
    }
    SetReversed(true);
    animationFraction_.SetDirectionAfterStart(ForwardDirection::REVERSE);
    Resume();
}


void RSRenderAnimation::SetReversed(bool isReversed)
{
    if (!IsPaused() && !IsRunning()) {
        ROSEN_LOGE("Failed to reverse animation, animation is not running!");
        return;
    }

    animationFraction_.SetDirectionAfterStart(isReversed ? ForwardDirection::REVERSE : ForwardDirection::NORMAL);
}

RSRenderNode* RSRenderAnimation::GetTarget() const
{
    return target_;
}

void RSRenderAnimation::SetFractionInner(float fraction)
{
    animationFraction_.UpdateRemainTimeFraction(fraction);
}

void RSRenderAnimation::ProcessFillModeOnStart(float startFraction)
{
    auto fillMode = GetFillMode();
    if (fillMode == FillMode::BACKWARDS || fillMode == FillMode::BOTH) {
        OnAnimate(startFraction);
    }
}

void RSRenderAnimation::ProcessFillModeOnFinish(float endFraction)
{
    auto fillMode = GetFillMode();
    if (fillMode == FillMode::FORWARDS || fillMode == FillMode::BOTH) {
        OnAnimate(endFraction);
    } else {
        OnRemoveOnCompletion();
    }
}

void RSRenderAnimation::ProcessOnRepeatFinish()
{
    std::unique_ptr<RSCommand> command =
        std::make_unique<RSAnimationCallback>(targetId_, id_, token_, REPEAT_FINISHED);
    RSMessageProcessor::Instance().AddUIMessage(ExtractPid(id_), command);
}

bool RSRenderAnimation::Animate(int64_t time)
{
    // calculateAnimationValue_ is embedded modify for stat animate frame drop
    calculateAnimationValue_ = true;

    if (!IsRunning()) {
        ROSEN_LOGD("RSRenderAnimation::Animate, IsRunning is false!");
        RS_OPTIONAL_TRACE_NAME_FMT("Animation[%llu] animate not running, state is [%d]", id_, state_);
        return state_ == AnimationState::FINISHED;
    }

    // set start time and return
    if (needUpdateStartTime_) {
        SetStartTime(time);
        return state_ == AnimationState::FINISHED;
    }

    // if time not changed since last frame, return
    if (time == animationFraction_.GetLastFrameTime()) {
        return state_ == AnimationState::FINISHED;
    }

    if (needInitialize_) {
        // normally this only run once, but in spring animation with blendDuration, it may run multiple times
        OnInitialize(time);
    }

    // calculate frame time interval in seconds
    float frameInterval = (time - animationFraction_.GetLastFrameTime()) * 1.0f / NS_TO_S;

    // convert time to fraction
    auto [fraction, isInStartDelay, isFinished, isRepeatFinished] = animationFraction_.GetAnimationFraction(time);
    if (isInStartDelay) {
        calculateAnimationValue_ = false;
        ProcessFillModeOnStart(fraction);
        ROSEN_LOGD("RSRenderAnimation::Animate, isInStartDelay is true");
        return false;
    }

    RecordLastAnimateValue();
    OnAnimate(fraction);
    DumpFraction(fraction, time);
    UpdateAnimateVelocity(frameInterval);

    if (isRepeatFinished) {
        ProcessOnRepeatFinish();
    }
    if (isFinished) {
        ProcessFillModeOnFinish(fraction);
        ROSEN_LOGD("RSRenderAnimation::Animate, isFinished is true");
        return true;
    }
    return isFinished;
}

void RSRenderAnimation::SetStartTime(int64_t time)
{
    time = RS_PROFILER_ANIME_SET_START_TIME(id_, time);
    animationFraction_.SetLastFrameTime(time);
    needUpdateStartTime_ = false;
}

const std::shared_ptr<RSRenderPropertyBase>& RSRenderAnimation::GetAnimateVelocity() const
{
    return animateVelocity_;
}

bool RSRenderAnimation::isCalcAnimateVelocity_ = true;
} // namespace Rosen
} // namespace OHOS
