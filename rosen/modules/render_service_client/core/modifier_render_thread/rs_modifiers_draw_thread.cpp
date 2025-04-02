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

#include "modifier_render_thread/rs_modifiers_draw_thread.h"

#ifdef ACCESSIBILITY_ENABLE
#include "transaction/rs_render_service_client.h"
#endif
#include "platform/common/rs_log.h"
#include "qos.h"
#include "render_context/shader_cache.h"
#include "modifier_render_thread/rs_modifiers_draw.h"
#include "command/rs_canvas_node_command.h"
#include "command/rs_command.h"
#include "command/rs_node_command.h"

#include "ffrt_inner.h"
#include "rs_frame_report.h"

namespace OHOS {
namespace Rosen {
constexpr uint32_t DEFAULT_MODIFIERS_DRAW_THREAD_LOOP_NUM = 3;
std::atomic<bool> RSModifiersDrawThread::isHybridRender_ = false;
RSModifiersDrawThread::RSModifiersDrawThread() {}

RSModifiersDrawThread::~RSModifiersDrawThread()
{
    if (!isStarted_) {
        return;
    }
    if (handler_ != nullptr) {
        handler_->RemoveAllEvents();
        handler_ = nullptr;
    }
    if (runner_ != nullptr) {
        runner_->Stop();
        runner_ = nullptr;
    }
#ifdef ACCESSIBILITY_ENABLE
    UnsubscribeHighContrastChange();
#endif
    RSModifiersDrawThread::isHybridRender_ = false;
}

RSModifiersDrawThread& RSModifiersDrawThread::Instance()
{
    static RSModifiersDrawThread instance;
    return instance;
}

void RSModifiersDrawThread::SetCacheDir(const std::string& path)
{
    auto& cache = ShaderCache::Instance();
    cache.SetFilePath(path);
}

#ifdef ACCESSIBILITY_ENABLE
void RSModifiersDrawThread::SubscribeHighContrastChange()
{
    if (!RSSystemProperties::GetHybridRenderEnable() || highContrastObserver_ != nullptr) {
        return;
    }
    auto& config = AccessibilityConfig::AccessibilityConfig::GetInstance();
    if (!config.InitializeContext()) {
        RS_LOGE("%{public}s AccessibilityConfig InitializeContext fail", __func__);
        return;
    }
    highContrastObserver_ = std::make_shared<Detail::HighContrastObserver>(highContrast_);
    // Non-system app, the first highContrast value in highContrastObserver_ is incorrect, so get it from RS.
    if (!highContrastObserver_->IsSystemApp()) {
        auto renderServiceClient =
            std::static_pointer_cast<RSRenderServiceClient>(RSIRenderClient::CreateRenderServiceClient());
        if (renderServiceClient != nullptr) {
            highContrast_ = renderServiceClient->GetHighContrastTextState();
        } else {
            RS_LOGE("%{public}s GetHighContrastTextState, renderServiceClient is null", __func__);
        }
    }
    config.SubscribeConfigObserver(AccessibilityConfig::CONFIG_ID::CONFIG_HIGH_CONTRAST_TEXT, highContrastObserver_);
}

void RSModifiersDrawThread::UnsubscribeHighContrastChange()
{
    if (highContrastObserver_ == nullptr) {
        return;
    }
    auto& config = AccessibilityConfig::AccessibilityConfig::GetInstance();
    if (!config.InitializeContext()) {
        RS_LOGE("%{public}s AccessibilityConfig InitializeContext fail", __func__);
    }
    config.UnsubscribeConfigObserver(AccessibilityConfig::CONFIG_ID::CONFIG_HIGH_CONTRAST_TEXT, highContrastObserver_);
    highContrastObserver_ = nullptr;
}

bool RSModifiersDrawThread::GetHighContrast()
{
    return highContrast_;
}
#endif

void RSModifiersDrawThread::Start()
{
    RSModifiersDrawThread::isHybridRender_ = true;
    std::lock_guard<std::mutex> lock(mutex_);
    if (isStarted_) {
        return;
    }
    runner_ = AppExecFwk::EventRunner::Create("ModifiersDraw");
    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
    runner_->Run();
#ifdef ACCESSIBILITY_ENABLE
    SubscribeHighContrastChange();
#endif
    isStarted_ = true;
    PostTask([] {
        RsFrameReport::GetInstance().ModifierReportSchedEvent(FrameSchedEvent::RS_MODIFIER_INFO, {});
        SetThreadQos(QOS::QosLevel::QOS_USER_INTERACTIVE);
        // Init shader cache
        std::string vkVersion = std::to_string(VK_API_VERSION_1_2);
        auto size = vkVersion.size();
        auto& cache = ShaderCache::Instance();
        cache.InitShaderCache(vkVersion.c_str(), size, true);
    });
    RS_LOGI("%{public}s RSModifiersDrawThread started", __func__);
}

void RSModifiersDrawThread::PostTask(const std::function<void()>&& task)
{
    if (!isStarted_) {
        Start();
    }
    if (handler_ != nullptr) {
        handler_->PostTask(task, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    }
}

bool RSModifiersDrawThread::TargetCommad(
    Drawing::DrawCmdList::HybridRenderType hybridRenderType, uint16_t type, uint16_t subType, bool cmdListEmpty)
{
    if (hybridRenderType == Drawing::DrawCmdList::HybridRenderType::NONE) {
        return false;
    }
    if (hybridRenderType != Drawing::DrawCmdList::HybridRenderType::CANVAS && cmdListEmpty) {
        return false;
    }
#ifdef ACCESSIBILITY_ENABLE
    if (RSModifiersDrawThread::Instance().GetHighContrast &&
        hybridRenderType == Drawing::DrawCmdList::HybridRenderType::TEXT) {
            return false;
        }
#endif
    bool targetCmd = false;
    switch (cmd->GetType()) {
        case RSCommandType::RS_NODE:
            if (subType == OHOS::Rosen::RSNodeCommandType::UPDATE_MODIFIER_DRAW_CMD_LIST ||
                subType == OHOS::Rosen::RSNodeCommandType::ADD_MODIFIER) {
                targetCmd = true;
            }
            break;
        case RSCommandType::CANVAS_NODE:
            if (subType == OHOS::Rosen::RSCanvasNodeCommandType::CANVAS_NODE_UPDATE_RECORDING) {
                targetCmd = true;
            }
            break;
        default:
            break;
    }
    return targetCmd;
}

std::unique_ptr<RSTransactionData>& RSModifiersDrawThread::ConvertTransaction(
    std::unique_ptr<RSTransactionData>& transactionData)
{
    static std::unique_ptr<ffrt::queue> queue = std::make_unique<ffrt::queue>(ffrt::queue_concurrent, "ModifiersDraw",
        ffrt::queue_attr().qos(ffrt::qos_user_interactive).max_concurrency(DEFAULT_MODIFIERS_DRAW_THREAD_LOOP_NUM));
    std::vector<ffrt::task_handle> handles;
    bool hasCanvasCmdList = false;
    for (auto& [nodeId, followType, command] : transactionData->GetPayload()) {
        auto drawCmdList = command == nullptr ? nullptr : command->GetDrawCmdList();
        if (drawCmdList == nullptr) {
            continue;
        }
        auto hybridRenderType = drawCmdList->GetHybridRenderType();
        if (!TargetCommad(hybridRenderType, command->GetType(), command->GetSubType(), drawCmdList->IsEmpty())) {
            continue;
        }

        RS_OPTIONAL_TRACE_NAME_FMT("RSModifiersDrawThread hybridRenderType=%d, width=%d, height=%d, nodeId=%" PRId64,
            hybridRenderType, drawCmdList->GetWidth(), drawCmdList->GetHeight(), command->GetNodeId());
        switch (hybridRenderType) {
            case Drawing::DrawCmdList::HybridRenderType::CANVAS:
                RSModifiersDraw::ConvertCmdListForCanvas(drawCmdList, command->GetNodeId());
                hasCanvasCmdList = true;
                break;
            case Drawing::DrawCmdList::HybridRenderType::TEXT:
            case Drawing::DrawCmdList::HybridRenderType::SVG:
            case Drawing::DrawCmdList::HybridRenderType::HMSYMBOL:
                if (RSSystemProperties::GetHybridRenderParallelConvertEnabled()) {
                    handles.emplace_back(queue->submit.h([cmdList = std::move(drawCmdList), nodeId = command->GetNodeId()]() {
                        RSModifiersDraw::ConvertCmdList(cmdList, nodeId);
                    }));
                } else {
                    RSModifiersDraw::ConvertCmdList(drawCmdList, command->GetNodeId());
                }
                break;
            default:
                break;
        }
    }
    if (hasCanvasCmdList) {
        RSModifiersDrawThread::Instance().ScheduleTask([] { RSModifiersDraw::CreateNextFrameSurface(); });
    }
    for (auto& handle : handles) {
        queue->wait(handle);
    }

    return transactionData;
}
} // namespace Rosen
} // namespace OHOS