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

#include "ui/rs_ui_context.h"

#include "command/rs_node_command.h"
#include "modifier/rs_modifier_manager_map.h"
#include "platform/common/rs_log.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_ui_context_manager.h"
#include "utils/typeface_map.h"

namespace OHOS {
namespace Rosen {
RSUIContext::RSUIContext(uint64_t token) : token_(token)
{
    rsTransactionHandler_ = std::make_shared<RSTransactionHandler>(token);
    rsSyncTransactionHandler_ = std::shared_ptr<RSSyncTransactionHandler>(new RSSyncTransactionHandler());
    rsSyncTransactionHandler_->SetTransactionHandler(rsTransactionHandler_);
}

RSUIContext::RSUIContext() : RSUIContext(0) {}

RSUIContext::~RSUIContext() {}

const std::shared_ptr<RSImplicitAnimator> RSUIContext::GetRSImplicitAnimator()
{
    std::lock_guard<std::mutex> lock(implicitAnimatorMutex_);
    auto it = rsImplicitAnimators_.find(gettid());
    if (it != rsImplicitAnimators_.end()) {
        return it->second;
    } else {
        if (rsImplicitAnimators_.size() > 0) {
            RS_LOGI_LIMIT("Too many threads are using the same animator");
        }
        auto rsImplicitAnimator = std::make_shared<RSImplicitAnimator>();
        rsImplicitAnimator->SetRSUIContext(weak_from_this());
        rsImplicitAnimators_.emplace(gettid(), rsImplicitAnimator);
        return rsImplicitAnimator;
    }
}

const std::shared_ptr<RSModifierManager> RSUIContext::GetRSModifierManager()
{
    if (rsModifierManager_ == nullptr) {
        rsModifierManager_ = std::make_shared<RSModifierManager>();
    }
    return rsModifierManager_;
}

bool RSUIContext::AnimationCallback(AnimationId animationId, AnimationCallbackEvent event)
{
    std::shared_ptr<RSAnimation> animation = nullptr;
    {
        std::unique_lock<std::recursive_mutex> lock(animationMutex_);
        auto animationItr = animations_.find(animationId);
        if (animationItr == animations_.end()) {
            ROSEN_LOGE("Failed to find animation[%{public}" PRIu64 "]!", animationId);
            return false;
        }
        animation = animationItr->second;
    }

    if (animation == nullptr) {
        ROSEN_LOGE("Failed to callback animation[%{public}" PRIu64 "], animation is null!", animationId);
        return false;
    }
    if (event == FINISHED) {
        RemoveAnimationInner(animation);
        animation->CallFinishCallback();
        return true;
    } else if (event == REPEAT_FINISHED) {
        animation->CallRepeatCallback();
        return true;
    } else if (event == LOGICALLY_FINISHED) {
        animation->CallLogicallyFinishCallback();
        return true;
    }
    ROSEN_LOGE("Failed to callback animation event[%{public}d], event is null!", event);
    return false;
}

void RSUIContext::AddAnimationInner(const std::shared_ptr<RSAnimation>& animation)
{
    std::unique_lock<std::recursive_mutex> lock(animationMutex_);
    animations_.emplace(animation->GetId(), animation);
    animatingPropertyNum_[animation->GetPropertyId()]++;
}

void RSUIContext::RemoveAnimationInner(const std::shared_ptr<RSAnimation>& animation)
{
    std::unique_lock<std::recursive_mutex> lock(animationMutex_);
    if (auto it = animatingPropertyNum_.find(animation->GetPropertyId()); it != animatingPropertyNum_.end()) {
        it->second--;
        if (it->second == 0) {
            animatingPropertyNum_.erase(it);
            animation->SetPropertyOnAllAnimationFinish();
        }
    }
    animations_.erase(animation->GetId());
}

void RSUIContext::SetUITaskRunner(const TaskRunner& uiTaskRunner)
{
    taskRunner_ = uiTaskRunner;
    if (rsTransactionHandler_) {
        rsTransactionHandler_->SetUITaskRunner(uiTaskRunner);
    }
}

void RSUIContext::PostTask(const std::function<void()>& task)
{
    PostDelayTask(task, 0);
}

void RSUIContext::PostDelayTask(const std::function<void()>& task, uint32_t delay)
{
    if (taskRunner_ == nullptr) {
        ROSEN_LOGW(
            "multi-instance RSUIContext::PostDelayTask failed, taskRunner is empty, token=%{public}" PRIu64, token_);
        auto ctx = RSUIContextManager::Instance().GetRandomUITaskRunnerCtx();
        if (ctx == nullptr) {
            ROSEN_LOGE("multi-instance RSUIContext::PostDelayTask, no taskRunner exists");
            return;
        }
        ctx->PostDelayTask(task, delay);
        return;
    }
    taskRunner_(task, delay);
    ROSEN_LOGD("multi-instance RSUIContext::PostDelayTask success token=%{public}" PRIu64, token_);
}

void RSUIContext::DumpNodeTreeProcessor(NodeId nodeId, pid_t pid, uint32_t taskId, std::string& out)
{
    auto transaction = GetRSTransaction();
    if (transaction) {
        out.append("transactionFlags:[ ")
            .append(std::to_string(pid))
            .append(", ")
            .append(std::to_string(transaction->GetTransactionDataIndex()))
            .append("]\r");
    }
    if (auto node = GetNodeMap().GetNode(nodeId)) {
        constexpr int TOP_LEVEL_DEPTH = 1;
        node->DumpTree(TOP_LEVEL_DEPTH, out);
    }
    if (transaction) {
        std::unique_ptr<RSCommand> command = std::make_unique<RSCommitDumpClientNodeTree>(nodeId, pid, taskId, out);
        transaction->AddCommand(command, true);
        transaction->FlushImplicitTransaction();
    }
}

namespace {
class TypefaceAutoRegister {
public:
    TypefaceAutoRegister()
    {
        std::function<bool(std::shared_ptr<Drawing::Typeface>)> registerTypefaceFunc =
            [](std::shared_ptr<Drawing::Typeface> typeface) -> bool {
            static Rosen::RSInterfaces& rsInterface = Rosen::RSInterfaces::GetInstance();
            return rsInterface.RegisterTypeface(typeface);
        };
        Drawing::Typeface::RegisterCallBackFunc(registerTypefaceFunc);

        std::function<void(uint32_t)> typefaceDestroyedFunc = [](uint32_t uniqueID) {
            static Rosen::RSInterfaces& rsInterface = Rosen::RSInterfaces::GetInstance();
            rsInterface.UnRegisterTypeface(uniqueID);
        };
        Drawing::Typeface::RegisterOnTypefaceDestroyed(typefaceDestroyedFunc);
        Drawing::Typeface::RegisterUniqueIDCallBack(TypefaceMap::GetTypefaceByUniqueID);
    }

    ~TypefaceAutoRegister()
    {
        Drawing::Typeface::RegisterCallBackFunc(nullptr);
        Drawing::Typeface::RegisterOnTypefaceDestroyed(nullptr);
        Drawing::Typeface::RegisterUniqueIDCallBack(nullptr);
    }
};

#ifndef ARKUI_X_ENABLE
// Prohibiting resigter the callback function in advance when arkui-x use custom's font
TypefaceAutoRegister g_typefaceAutoRegister;
#endif
} // namespace
} // namespace Rosen
} // namespace OHOS