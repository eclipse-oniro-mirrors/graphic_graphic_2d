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

#include "rs_render_service_connection_stub.h"
#include <memory>
#include <mutex>
#include "ivsync_connection.h"
#ifdef RES_SCHED_ENABLE
#include "res_sched_client.h"
#include "res_type.h"
#include <sched.h>
#endif
#include "securec.h"
#include "sys_binder.h"

#include "command/rs_command_factory.h"
#include "command/rs_command_verify_helper.h"
#include "common/rs_xcollie.h"
#include "hgm_frame_rate_manager.h"
#include "memory/rs_memory_flow_control.h"
#include "pipeline/rs_base_render_util.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "pipeline/rs_unmarshal_thread.h"
#include "platform/common/rs_log.h"
#include "transaction/rs_ashmem_helper.h"
#include "render/rs_typeface_cache.h"
#include "rs_trace.h"
#include "rs_profiler.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr size_t MAX_DATA_SIZE_FOR_UNMARSHALLING_IN_PLACE = 1024 * 15; // 15kB
constexpr size_t FILE_DESCRIPTOR_LIMIT = 15;
constexpr size_t MAX_OBJECTNUM = 512;
constexpr size_t MAX_DATA_SIZE = 1024 * 1024; // 1MB
static constexpr int MAX_SECURITY_EXEMPTION_LIST_NUMBER = 1024; // securityExemptionList size not exceed 1024
#ifdef RES_SCHED_ENABLE
const uint32_t RS_IPC_QOS_LEVEL = 7;
constexpr const char* RS_BUNDLE_NAME = "render_service";
#endif
static constexpr std::array descriptorCheckList = {
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_FOCUS_APP_INFO),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_DEFAULT_SCREEN_ID),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ACTIVE_SCREEN_ID),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ALL_SCREEN_IDS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_VIRTUAL_SCREEN),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_RESOLUTION),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_SURFACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_BLACKLIST),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::ADD_VIRTUAL_SCREEN_BLACKLIST),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REMOVE_VIRTUAL_SCREEN_BLACKLIST),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_SECURITY_EXEMPTION_LIST),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_SECURITY_MASK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_MIRROR_SCREEN_VISIBLE_RECT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REMOVE_VIRTUAL_SCREEN),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_CHANGE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_ACTIVE_MODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_REFRESH_RATE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_REFRESH_RATE_MODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SYNC_FRAME_RATE_RANGE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_FRAME_RATE_LINKER),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_CURRENT_REFRESH_RATE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_CURRENT_REFRESH_RATE_MODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_REFRESH_RATES),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SHOW_REFRESH_RATE_ENABLED),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SHOW_REFRESH_RATE_ENABLED),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::MARK_POWER_OFF_NEED_PROCESS_ONE_FRAME),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPAINT_EVERYTHING),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::FORCE_REFRESH_ONE_FRAME_WITH_NEXT_VSYNC),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::DISABLE_RENDER_CONTROL_SCREEN),
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_COLOR_INVERSION_CONFIG),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_COLOR_INVERSION_ENABLED),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_POINTER_LUMINANCE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_POINTER_LUMINANCE_CALLBACK),
#endif
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_POWER_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_BACK_LIGHT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_ACTIVE_MODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_MODES),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_CAPABILITY),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_POWER_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_BACK_LIGHT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_DATA),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_VIRTUAL_SCREEN_RESOLUTION),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_AVAILABLE_LISTENER),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_CLEAR_LISTENER),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_GAMUTS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_METADATAKEYS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_GAMUT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_GAMUT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_GAMUT_MAP),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_CORRECTION),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_MIRROR_SCREEN_CANVAS_ROTATION),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_MIRROR_SCREEN_SCALE_MODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_GLOBAL_DARK_COLOR_MODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_GAMUT_MAP),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_PIXEL_MAP_FROM_SURFACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_HDR_CAPABILITY),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_PIXEL_FORMAT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_PIXEL_FORMAT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_HDR_FORMATS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_HDR_FORMAT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_HDR_FORMAT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_COLORSPACES),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_COLORSPACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_COLORSPACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_TYPE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_SKIP_FRAME_INTERVAL),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_REFRESH_RATE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_ACTIVE_RECT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_OCCLUSION_CHANGE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_APP_WINDOW_NUM),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SYSTEM_ANIMATED_SCENES),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_WATERMARK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SHOW_WATERMARK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::RESIZE_VIRTUAL_SCREEN),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHIC),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHICS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_TOTAL_APP_MEM_SIZE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_JANK_STATS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_BITMAP),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_PIXELMAP),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::EXECUTE_SYNCHRONOUS_TASK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_LIGHT_FACTOR_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_PACKAGE_EVENT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_REFRESH_RATE_EVENT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_SOFT_VSYNC_EVENT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_RESPONSE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_COMPLETE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_JANK_FRAME),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_GAMESTATE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_TOUCH_EVENT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_DYNAMIC_MODE_EVENT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_HARDWARE_ENABLED),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_HIDE_PRIVACY_CONTENT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_SURFACE_OCCLUSION_CHANGE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_SURFACE_OCCLUSION_CHANGE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_HGM_CFG_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_ROTATION_CACHE_ENABLED),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_SCREEN_SWITCHED),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_TP_FEATURE_CONFIG),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_USING_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REFRESH_RATE_MODE_CHANGE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_CURTAIN_SCREEN_USING_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::DROP_FRAME_BY_PID),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_TYPEFACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_TYPEFACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REFRESH_RATE_UPDATE_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_FRAME_RATE_LINKER_EXPECTED_FPS_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ACTIVE_DIRTY_REGION_INFO),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_GLOBAL_DIRTY_REGION_INFO),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_LAYER_COMPOSE_INFO),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_CAST_SCREEN_ENABLE_SKIP_WINDOW),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_UIEXTENSION_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VMA_CACHE_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_ANCO_FORCE_DO_DIRECT),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NEED_REGISTER_TYPEFACE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_DISPLAY_NODE),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_FREE_MULTI_WINDOW_STATUS),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_SURFACE_BUFFER_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_SURFACE_BUFFER_CALLBACK),
    static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_LAYER_TOP),
};

void CopyFileDescriptor(MessageParcel& old, MessageParcel& copied)
{
    binder_size_t* object = reinterpret_cast<binder_size_t*>(old.GetObjectOffsets());
    binder_size_t* copiedObject = reinterpret_cast<binder_size_t*>(copied.GetObjectOffsets());

    size_t objectNum = old.GetOffsetsSize();

    uintptr_t data = old.GetData();
    uintptr_t copiedData = copied.GetData();

    for (size_t i = 0; i < objectNum; i++) {
        const flat_binder_object* flat = reinterpret_cast<flat_binder_object*>(data + object[i]);
        flat_binder_object* copiedFlat = reinterpret_cast<flat_binder_object*>(copiedData + copiedObject[i]);

        if (flat->hdr.type == BINDER_TYPE_FD && flat->handle >= 0) {
            int32_t val = dup(flat->handle);
            if (val < 0) {
                ROSEN_LOGW("CopyFileDescriptor dup failed, fd:%{public}d, handle:%{public}" PRIu32, val,
                    static_cast<uint32_t>(flat->handle));
            }
            copiedFlat->handle = static_cast<uint32_t>(val);
        }
    }
}

std::shared_ptr<MessageParcel> CopyParcelIfNeed(MessageParcel& old, pid_t callingPid)
{
    if (RSSystemProperties::GetCacheEnabledForRotation() &&
        RSMainThread::Instance()->GetDesktopPidForRotationScene() != callingPid) {
        return nullptr;
    }
    auto dataSize = old.GetDataSize();
    if (dataSize <= MAX_DATA_SIZE_FOR_UNMARSHALLING_IN_PLACE && old.GetOffsetsSize() < FILE_DESCRIPTOR_LIMIT) {
        return nullptr;
    }
    if (dataSize > MAX_DATA_SIZE) {
        return nullptr;
    }
    if (dataSize == 0) {
        return nullptr;
    }

    if (old.GetOffsetsSize() > MAX_OBJECTNUM) {
        ROSEN_LOGW("RSRenderServiceConnectionStub::CopyParcelIfNeed failed, parcel fdCnt: %{public}zu is too large",
            old.GetOffsetsSize());
        return nullptr;
    }

    RS_TRACE_NAME("CopyParcelForUnmarsh: size:" + std::to_string(dataSize));
    void* base = malloc(dataSize);
    if (base == nullptr) {
        RS_LOGE("RSRenderServiceConnectionStub::CopyParcelIfNeed malloc failed");
        return nullptr;
    }
    if (memcpy_s(base, dataSize, reinterpret_cast<void*>(old.GetData()), dataSize) != 0) {
        RS_LOGE("RSRenderServiceConnectionStub::CopyParcelIfNeed copy parcel data failed");
        free(base);
        return nullptr;
    }

    auto parcelCopied = RS_PROFILER_COPY_PARCEL(old);
    if (!parcelCopied->ParseFrom(reinterpret_cast<uintptr_t>(base), dataSize)) {
        RS_LOGE("RSRenderServiceConnectionStub::CopyParcelIfNeed ParseFrom failed");
        free(base);
        return nullptr;
    }

    auto objectNum = old.GetOffsetsSize();
    if (objectNum != 0) {
        parcelCopied->InjectOffsets(old.GetObjectOffsets(), objectNum);
        CopyFileDescriptor(old, *parcelCopied);
    }
    if (parcelCopied->ReadInt32() != 0) {
        RS_LOGE("RSRenderServiceConnectionStub::CopyParcelIfNeed parcel data not match");
        return nullptr;
    }
    return parcelCopied;
}

bool CheckCreateNodeAndSurface(pid_t pid, RSSurfaceNodeType nodeType, SurfaceWindowType windowType)
{
    constexpr int nodeTypeMin = static_cast<int>(RSSurfaceNodeType::DEFAULT);
    constexpr int nodeTypeMax = static_cast<int>(RSSurfaceNodeType::UI_EXTENSION_SECURE_NODE);

    int typeNum = static_cast<int>(nodeType);
    if (typeNum < nodeTypeMin || typeNum > nodeTypeMax) {
        RS_LOGW("CREATE_NODE_AND_SURFACE invalid RSSurfaceNodeType");
        return false;
    }
    if (windowType != SurfaceWindowType::DEFAULT_WINDOW && windowType != SurfaceWindowType::SYSTEM_SCB_WINDOW) {
        RS_LOGW("CREATE_NODE_AND_SURFACE invalid SurfaceWindowType");
        return false;
    }

    bool isTokenTypeValid = true;
    bool isNonSystemAppCalling = false;
    RSInterfaceCodeAccessVerifierBase::GetAccessType(isTokenTypeValid, isNonSystemAppCalling);
    if (isNonSystemAppCalling) {
        if (nodeType != RSSurfaceNodeType::DEFAULT &&
            nodeType != RSSurfaceNodeType::APP_WINDOW_NODE &&
            nodeType != RSSurfaceNodeType::SELF_DRAWING_NODE &&
            nodeType != RSSurfaceNodeType::UI_EXTENSION_COMMON_NODE) {
            RS_LOGW("CREATE_NODE_AND_SURFACE NonSystemAppCalling invalid RSSurfaceNodeType %{public}d, pid %d",
                typeNum, pid);
            return false;
        }
        if (windowType != SurfaceWindowType::DEFAULT_WINDOW) {
            RS_LOGW("CREATE_NODE_AND_SURFACE NonSystemAppCalling invalid SurfaceWindowType %{public}d, pid %d",
                static_cast<int>(windowType), pid);
            return false;
        }
    }

    return true;
}

bool IsValidCallingPid(pid_t pid, pid_t callingPid)
{
    return (callingPid == getpid()) || (callingPid == pid);
}

}

void RSRenderServiceConnectionStub::SetQos()
{
#ifdef RES_SCHED_ENABLE
    std::string strBundleName = RS_BUNDLE_NAME;
    std::string strPid = std::to_string(getpid());
    std::string strTid = std::to_string(gettid());
    std::string strQos = std::to_string(RS_IPC_QOS_LEVEL);
    std::unordered_map<std::string, std::string> mapPayload;
    mapPayload["pid"] = strPid;
    mapPayload[strTid] = strQos;
    mapPayload["bundleName"] = strBundleName;
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        OHOS::ResourceSchedule::ResType::RES_TYPE_THREAD_QOS_CHANGE, 0, mapPayload);
    struct sched_param param = {0};
    param.sched_priority = 1;
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        RS_LOGE("RSRenderServiceConnectionStub Couldn't set SCHED_FIFO.");
    } else {
        RS_LOGI("RSRenderServiceConnectionStub set SCHED_FIFO succeed.");
    }
#endif
}

int RSRenderServiceConnectionStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    RS_PROFILER_ON_REMOTE_REQUEST(this, code, data, reply, option);

    AshmemFdContainer::SetIsUnmarshalThread(false);
    pid_t callingPid = GetCallingPid();
    RSMarshallingHelper::SetCallingPid(callingPid);
    auto tid = gettid();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tids_.find(tid) == tids_.end()) {
            SetQos();
            tids_.insert(tid);
        }
    }
    if (std::find(std::cbegin(descriptorCheckList), std::cend(descriptorCheckList), code) !=
        std::cend(descriptorCheckList)) {
        auto token = data.ReadInterfaceToken();
        if (token != RSIRenderServiceConnection::GetDescriptor()) {
            if (code == static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_PIXEL_MAP_FROM_SURFACE)) {
                if (!reply.WriteInt32(0)) {
                    return ERR_INVALID_REPLY;
                }
            }
            return ERR_INVALID_STATE;
        }
    }
    auto accessible = securityManager_.IsInterfaceCodeAccessible(code);
    if (!accessible && code != static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::TAKE_SURFACE_CAPTURE) &&
        code != static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHIC) &&
        code != static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_REFRESH_INFO) &&
        code != static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_AVAILABLE_LISTENER) &&
        code != static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_CLEAR_LISTENER)) {
        RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest no permission code:%{public}d", code);
        return ERR_INVALID_STATE;
    }
    int ret = ERR_NONE;
    switch (code) {
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::COMMIT_TRANSACTION): {
            bool isTokenTypeValid = true;
            bool isNonSystemAppCalling = false;
            RSInterfaceCodeAccessVerifierBase::GetAccessType(isTokenTypeValid, isNonSystemAppCalling);
            if (!isTokenTypeValid) {
                RS_LOGE("RSRenderServiceConnectionStub::COMMIT_TRANSACTION invalid token type");
                return ERR_INVALID_STATE;
            }
            if (isNonSystemAppCalling) {
                RsCommandVerifyHelper::GetInstance().RegisterNonSystemPid(callingPid);
            }
            RS_TRACE_NAME_FMT("Recv Parcel Size:%zu, fdCnt:%zu", data.GetDataSize(), data.GetOffsetsSize());
            static bool isUniRender = RSUniRenderJudgement::IsUniRender();
            std::shared_ptr<MessageParcel> parsedParcel;
            std::unique_ptr<AshmemFdWorker> ashmemFdWorker = nullptr;
            std::shared_ptr<AshmemFlowControlUnit> ashmemFlowControlUnit = nullptr;
            if (data.ReadInt32() == 0) { // indicate normal parcel
                if (isUniRender) {
                    // in uni render mode, if parcel size over threshold,
                    // Unmarshalling task will be post to RSUnmarshalThread,
                    // copy the origin parcel to maintain the parcel lifetime
                    parsedParcel = CopyParcelIfNeed(data, callingPid);
                }
                if (parsedParcel == nullptr) {
                    // no need to copy or copy failed, use original parcel
                    // execute Unmarshalling immediately
                    auto transactionData = RSBaseRenderUtil::ParseTransactionData(data);
                    if (transactionData && isNonSystemAppCalling) {
                        const auto& nodeMap = RSMainThread::Instance()->GetContext().GetNodeMap();
                        if (!transactionData->IsCallingPidValid(callingPid, nodeMap)) {
                            RS_LOGE("RSRenderServiceConnectionStub::COMMIT_TRANSACTION IsCallingPidValid check failed");
                        }
                    }
                    CommitTransaction(transactionData);
                    break;
                }
            } else {
                // indicate ashmem parcel
                // should be parsed to normal parcel before Unmarshalling
                parsedParcel = RSAshmemHelper::ParseFromAshmemParcel(&data, ashmemFdWorker, ashmemFlowControlUnit,
                    callingPid);
            }
            if (parsedParcel == nullptr) {
                RS_LOGE("RSRenderServiceConnectionStub::COMMIT_TRANSACTION failed: parsed parcel is nullptr");
                return ERR_INVALID_DATA;
            }
            if (isUniRender) {
                // post Unmarshalling task to RSUnmarshalThread
                RSUnmarshalThread::Instance().RecvParcel(parsedParcel, isNonSystemAppCalling, callingPid,
                    std::move(ashmemFdWorker), ashmemFlowControlUnit);
            } else {
                // execute Unmarshalling immediately
                auto transactionData = RSBaseRenderUtil::ParseTransactionData(*parsedParcel);
                if (transactionData && isNonSystemAppCalling) {
                    const auto& nodeMap = RSMainThread::Instance()->GetContext().GetNodeMap();
                    if (!transactionData->IsCallingPidValid(callingPid, nodeMap)) {
                        RS_LOGE("RSRenderServiceConnectionStub::COMMIT_TRANSACTION IsCallingPidValid check failed");
                    }
                }
                CommitTransaction(transactionData);
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_UNI_RENDER_ENABLED): {
            if (!reply.WriteBool(GetUniRenderEnabled())) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_NODE): {
            auto nodeId = data.ReadUint64();
            bool isNonSystemCalling = false;
            bool isTokenTypeValid = true;
            RSInterfaceCodeAccessVerifierBase::GetAccessType(isTokenTypeValid, isNonSystemCalling);
            if (isNonSystemCalling && !IsValidCallingPid(ExtractPid(nodeId), callingPid)) {
                RS_LOGW("CREATE_NODE invalid nodeId[%{public}" PRIu64 "] pid[%{public}d]", nodeId, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, nodeId);
            auto surfaceName = data.ReadString();
            RSSurfaceRenderNodeConfig config = {.id = nodeId, .name = surfaceName};
            if (!reply.WriteBool(CreateNode(config))) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_NODE_AND_SURFACE): {
            auto nodeId = data.ReadUint64();
            if (!IsValidCallingPid(ExtractPid(nodeId), callingPid)) {
                RS_LOGW("CREATE_NODE_AND_SURFACE invalid nodeId[%" PRIu64 "] pid[%d]", nodeId, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, nodeId);
            auto surfaceName = data.ReadString();
            auto type = static_cast<RSSurfaceNodeType>(data.ReadUint8());
            bool isTextureExportNode = data.ReadBool();
            bool isSync = data.ReadBool();
            auto surfaceWindowType = static_cast<SurfaceWindowType>(data.ReadUint8());
            if (!CheckCreateNodeAndSurface(callingPid, type, surfaceWindowType)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSSurfaceRenderNodeConfig config = {
                .id = nodeId, .name = surfaceName, .nodeType = type,
                .isTextureExportNode = isTextureExportNode, .isSync = isSync,
                .surfaceWindowType = surfaceWindowType};
            sptr<Surface> surface = CreateNodeAndSurface(config);
            if (surface == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            auto producer = surface->GetProducer();
            if (!reply.WriteRemoteObject(producer->AsObject())) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_FOCUS_APP_INFO): {
            int32_t pid{0};
            if (!data.ReadInt32(pid)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_PID(data, pid);
            int32_t uid{0};
            std::string bundleName;
            std::string abilityName;
            uint64_t focusNodeId{0};
            if (!data.ReadInt32(uid) || !data.ReadString(bundleName) ||
                !data.ReadString(abilityName) || !data.ReadUint64(focusNodeId)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, focusNodeId);
            int32_t status = SetFocusAppInfo(pid, uid, bundleName, abilityName, focusNodeId);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_DEFAULT_SCREEN_ID): {
            ScreenId id = GetDefaultScreenId();
            if (!reply.WriteUint64(id)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ACTIVE_SCREEN_ID): {
            ScreenId id = GetActiveScreenId();
            if (!reply.WriteUint64(id)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ALL_SCREEN_IDS): {
            std::vector<ScreenId> ids = GetAllScreenIds();
            if (!reply.WriteUint32(ids.size())) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            for (uint32_t i = 0; i < ids.size(); i++) {
                if (!reply.WriteUint64(ids[i])) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_VIRTUAL_SCREEN): {
            // read the parcel data.
            std::string name;
            uint32_t width{0};
            uint32_t height{0};
            bool useSurface{false};
            if (!data.ReadString(name) || !data.ReadUint32(width) ||
                !data.ReadUint32(height) || !data.ReadBool(useSurface)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            sptr<Surface> surface = nullptr;
            if (useSurface) {
                auto remoteObject = data.ReadRemoteObject();
                if (remoteObject != nullptr) {
                    auto bufferProducer = iface_cast<IBufferProducer>(remoteObject);
                    surface = Surface::CreateSurfaceAsProducer(bufferProducer);
                }
            }
            ScreenId mirrorId{INVALID_SCREEN_ID};
            int32_t flags{0};
            std::vector<NodeId> whiteList;
            if (!data.ReadUint64(mirrorId) || !data.ReadInt32(flags) || !data.ReadUInt64Vector(&whiteList)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ScreenId id = CreateVirtualScreen(name, width, height, surface, mirrorId, flags, whiteList);
            if (!reply.WriteUint64(id)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_BLACKLIST): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            std::vector<NodeId> blackListVector;
            if (!data.ReadUint64(id) || !data.ReadUInt64Vector(&blackListVector)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = SetVirtualScreenBlackList(id, blackListVector);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::ADD_VIRTUAL_SCREEN_BLACKLIST): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            std::vector<NodeId> blackListVector;
            if (!data.ReadUint64(id) || !data.ReadUInt64Vector(&blackListVector)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = AddVirtualScreenBlackList(id, blackListVector);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REMOVE_VIRTUAL_SCREEN_BLACKLIST): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            std::vector<NodeId> blackListVector;
            if (!data.ReadUint64(id) || !data.ReadUInt64Vector(&blackListVector)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = RemoveVirtualScreenBlackList(id, blackListVector);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_SECURITY_EXEMPTION_LIST): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            std::vector<NodeId> securityExemptionList;
            if (!data.ReadUint64(id) || !data.ReadUInt64Vector(&securityExemptionList)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (securityExemptionList.size() > MAX_SECURITY_EXEMPTION_LIST_NUMBER) {
                RS_LOGE("RSRenderServiceConnectionStub::SET_VIRTUAL_SCREEN_SECURITY_EXEMPTION_LIST"
                    " failed: too many lists.");
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = SetVirtualScreenSecurityExemptionList(id, securityExemptionList);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_SECURITY_MASK): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            bool enable{false};
            if (!data.ReadUint64(id) || !data.ReadBool(enable)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::shared_ptr<Media::PixelMap> securityMask{nullptr};
            if (enable) {
                securityMask = std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
            }
            int32_t result = SetScreenSecurityMask(id, std::move(securityMask));
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_MIRROR_SCREEN_VISIBLE_RECT): {
            // read the parcel data.
            ScreenId id = INVALID_SCREEN_ID;
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            int32_t x = -1;
            int32_t y = -1;
            int32_t w = -1;
            int32_t h = -1;
            if (!data.ReadInt32(x) || !data.ReadInt32(y) ||
                !data.ReadInt32(w) || !data.ReadInt32(h)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            auto mainScreenRect = Rect {
                .x = x,
                .y = y,
                .w = w,
                .h = h
            };
            int32_t status = SetMirrorScreenVisibleRect(id, mainScreenRect);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_CAST_SCREEN_ENABLE_SKIP_WINDOW): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            bool enable{false};
            if (!data.ReadUint64(id) || !data.ReadBool(enable)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t result = SetCastScreenEnableSkipWindow(id, enable);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_SURFACE): {
            // read the parcel data.
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            auto bufferProducer = iface_cast<IBufferProducer>(remoteObject);
            sptr<Surface> surface = Surface::CreateSurfaceAsProducer(bufferProducer);
            if (surface == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = SetVirtualScreenSurface(id, surface);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REMOVE_VIRTUAL_SCREEN): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RemoveVirtualScreen(id);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_CHANGE_CALLBACK): {
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIScreenChangeCallback> cb = iface_cast<RSIScreenChangeCallback>(remoteObject);
            if (cb == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = SetScreenChangeCallback(cb);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_COLOR_INVERSION_CONFIG): {
            float darkBuffer = data.ReadFloat();
            float brightBuffer = data.ReadFloat();
            int64_t interval = data.ReadInt64();
            int32_t rangeSize = data.ReadInt32();
            int32_t status = SetPointerColorInversionConfig(darkBuffer, brightBuffer, interval, rangeSize);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_COLOR_INVERSION_ENABLED): {
            bool enable = data.ReadBool();
            int32_t status = SetPointerColorInversionEnabled(enable);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_POINTER_LUMINANCE_CALLBACK): {
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIPointerLuminanceChangeCallback> cb = iface_cast<RSIPointerLuminanceChangeCallback>(remoteObject);
            if (cb == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = RegisterPointerLuminanceChangeCallback(cb);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_POINTER_LUMINANCE_CALLBACK): {
            int32_t status = UnRegisterPointerLuminanceChangeCallback();
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
#endif
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_ACTIVE_MODE): {
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t modeId{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(modeId)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetScreenActiveMode(id, modeId);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_REFRESH_RATE): {
            ScreenId id{INVALID_SCREEN_ID};
            int32_t sceneId{0};
            int32_t rate{0};
            if (!data.ReadUint64(id) || !data.ReadInt32(sceneId) || !data.ReadInt32(rate)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetScreenRefreshRate(id, sceneId, rate);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_REFRESH_RATE_MODE): {
            int32_t mode{0};
            if (!data.ReadInt32(mode)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetRefreshRateMode(mode);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SYNC_FRAME_RATE_RANGE): {
            FrameRateLinkerId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (ExtractPid(id) != callingPid) {
                RS_LOGW("The SyncFrameRateRange isn't legal, frameRateLinkerId: %{public}" PRIu64
                    ", callingPid:%{public}d", id, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            uint32_t min{0};
            uint32_t max{0};
            uint32_t preferred{0};
            uint32_t type{0};
            uint32_t componentScene{0};
            int32_t animatorExpectedFrameRate{0};
            if (!data.ReadUint32(min) || !data.ReadUint32(max) || !data.ReadUint32(preferred) ||
                !data.ReadUint32(type) || !data.ReadUint32(componentScene) ||
                !data.ReadInt32(animatorExpectedFrameRate)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SyncFrameRateRange(id, {min, max, preferred, type, static_cast<ComponentScene>(componentScene)},
                animatorExpectedFrameRate);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_FRAME_RATE_LINKER): {
            FrameRateLinkerId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (ExtractPid(id) != callingPid) {
                RS_LOGW("The UnregisterFrameRateLinker isn't legal, frameRateLinkerId: %{public}" PRIu64
                    ", callingPid:%{public}d", id, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            UnregisterFrameRateLinker(id);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_CURRENT_REFRESH_RATE): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            uint32_t refreshRate = GetScreenCurrentRefreshRate(id);
            if (!reply.WriteUint32(refreshRate)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_CURRENT_REFRESH_RATE_MODE): {
            int32_t refreshRateMode = GetCurrentRefreshRateMode();
            if (!reply.WriteInt32(refreshRateMode)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_REFRESH_RATES): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::vector<int32_t> rates = GetScreenSupportedRefreshRates(id);
            if (!reply.WriteUint64(static_cast<uint64_t>(rates.size()))) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            for (auto ratesIter : rates) {
                if (!reply.WriteInt32(ratesIter)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SHOW_REFRESH_RATE_ENABLED): {
            bool enable = GetShowRefreshRateEnabled();
            if (!reply.WriteBool(enable)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SHOW_REFRESH_RATE_ENABLED): {
            bool enable{false};
            if (!data.ReadBool(enable)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetShowRefreshRateEnabled(enable);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_REFRESH_INFO): {
            auto token = data.ReadInterfaceToken();
            if (token != RSIRenderServiceConnection::GetDescriptor()) {
                ret = ERR_INVALID_STATE;
                break;
            }
            pid_t pid = data.ReadInt32();
            if (!IsValidCallingPid(pid, callingPid)) {
                RS_LOGW("GET_REFRESH_INFO invalid pid[%{public}d]", callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            std::string refreshInfo = GetRefreshInfo(pid);
            if (!reply.WriteString(refreshInfo)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_RESOLUTION): {
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t width{0};
            uint32_t height{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(width) || !data.ReadUint32(height)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = SetVirtualScreenResolution(id, width, height);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::MARK_POWER_OFF_NEED_PROCESS_ONE_FRAME): {
            MarkPowerOffNeedProcessOneFrame();
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPAINT_EVERYTHING): {
            RepaintEverything();
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::FORCE_REFRESH_ONE_FRAME_WITH_NEXT_VSYNC): {
            ForceRefreshOneFrameWithNextVSync();
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::DISABLE_RENDER_CONTROL_SCREEN): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            DisablePowerOffRenderControl(id);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_POWER_STATUS): {
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t status{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(status)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetScreenPowerStatus(id, static_cast<ScreenPowerStatus>(status));
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::TAKE_SURFACE_CAPTURE): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                RS_LOGE("RSRenderServiceConnectionStub::TakeSurfaceCapture remoteObject is nullptr");
                break;
            }
            sptr<RSISurfaceCaptureCallback> cb = iface_cast<RSISurfaceCaptureCallback>(remoteObject);
            if (cb == nullptr) {
                ret = ERR_NULL_OBJECT;
                RS_LOGE("RSRenderServiceConnectionStub::TakeSurfaceCapture cb is nullptr");
                break;
            }
            RSSurfaceCaptureConfig captureConfig;
            RSSurfaceCaptureBlurParam blurParam;
            if (!ReadSurfaceCaptureConfig(captureConfig, data)) {
                ret = ERR_INVALID_DATA;
                RS_LOGE("RSRenderServiceConnectionStub::TakeSurfaceCapture read captureConfig failed");
                break;
            }
            if (!ReadSurfaceCaptureBlurParam(blurParam, data)) {
                ret = ERR_INVALID_DATA;
                RS_LOGE("RSRenderServiceConnectionStub::TakeSurfaceCapture read blurParam failed");
                break;
            }
            RSSurfaceCapturePermissions permissions;
            permissions.screenCapturePermission = accessible;
            permissions.isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
                RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ + "::TAKE_SURFACE_CAPTURE");
            // Since GetCallingPid interface always returns 0 in asynchronous binder in Linux kernel system,
            // we temporarily add a white list to avoid abnormal functionality or abnormal display.
            // The white list will be removed after GetCallingPid interface can return real PID.
            permissions.selfCapture = (ExtractPid(id) == callingPid || callingPid == 0);
            TakeSurfaceCapture(id, cb, captureConfig, blurParam, permissions);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_WINDOW_FREEZE_IMMEDIATELY): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            bool isFreeze{false};
            if (!data.ReadBool(isFreeze)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            sptr<RSISurfaceCaptureCallback> cb;
            RSSurfaceCaptureConfig captureConfig;
            RSSurfaceCaptureBlurParam blurParam;
            if (isFreeze) {
                auto remoteObject = data.ReadRemoteObject();
                if (remoteObject == nullptr) {
                    ret = ERR_NULL_OBJECT;
                    RS_LOGE("RSRenderServiceConnectionStub::SET_WINDOW_FREEZE_IMMEDIATELY remoteObject is nullptr");
                    break;
                }
                cb = iface_cast<RSISurfaceCaptureCallback>(remoteObject);
                if (cb == nullptr) {
                    ret = ERR_NULL_OBJECT;
                    RS_LOGE("RSRenderServiceConnectionStub::SET_WINDOW_FREEZE_IMMEDIATELY cb is nullptr");
                    break;
                }
                if (!ReadSurfaceCaptureConfig(captureConfig, data)) {
                    ret = ERR_INVALID_DATA;
                    RS_LOGE("RSRenderServiceConnectionStub::SET_WINDOW_FREEZE_IMMEDIATELY write captureConfig failed");
                    break;
                }
                if (!ReadSurfaceCaptureBlurParam(blurParam, data)) {
                    ret = ERR_INVALID_DATA;
                    RS_LOGE("RSRenderServiceConnectionStub::TakeSurfaceCapture read blurParam failed");
                    break;
                }
            }
            SetWindowFreezeImmediately(id, isFreeze, cb, captureConfig, blurParam);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_POSITION): {
            NodeId id = data.ReadUint64();
            RS_PROFILER_PATCH_NODE_ID(data, id);
            float positionX = data.ReadFloat();
            float positionY = data.ReadFloat();
            float positionZ = data.ReadFloat();
            float positionW = data.ReadFloat();
            SetHwcNodeBounds(id, positionX, positionY, positionZ, positionW);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_APPLICATION_AGENT): {
            pid_t pid = GetCallingPid();
            RS_PROFILER_PATCH_PID(data, pid);
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<IApplicationAgent> app = iface_cast<IApplicationAgent>(remoteObject);
            if (app == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            RegisterApplicationAgent(pid, app);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_VIRTUAL_SCREEN_RESOLUTION): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSVirtualScreenResolution virtualScreenResolution = GetVirtualScreenResolution(id);
            if (!reply.WriteParcelable(&virtualScreenResolution)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_ACTIVE_MODE): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSScreenModeInfo screenModeInfo = GetScreenActiveMode(id);
            if (!reply.WriteParcelable(&screenModeInfo)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_MODES): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::vector<RSScreenModeInfo> screenSupportedModes = GetScreenSupportedModes(id);
            if (!reply.WriteUint64(static_cast<uint64_t>(screenSupportedModes.size()))) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            for (uint32_t modeIndex = 0; modeIndex < screenSupportedModes.size(); modeIndex++) {
                if (!reply.WriteParcelable(&screenSupportedModes[modeIndex])) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHIC): {
            int32_t pid{0};
            if (!data.ReadInt32(pid)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_PID(data, pid);
            if (!IsValidCallingPid(pid, callingPid)) {
                RS_LOGW("GET_MEMORY_GRAPHIC invalid pid[%{public}d]", callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            MemoryGraphic memoryGraphic = GetMemoryGraphic(pid);
            if (!reply.WriteParcelable(&memoryGraphic)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHICS): {
            std::vector<MemoryGraphic> memoryGraphics = GetMemoryGraphics();
            if (!reply.WriteUint64(static_cast<uint64_t>(memoryGraphics.size()))) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            for (uint32_t index = 0; index < memoryGraphics.size(); index++) {
                if (!reply.WriteParcelable(&memoryGraphics[index])) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_TOTAL_APP_MEM_SIZE): {
            float cpuMemSize = 0.f;
            float gpuMemSize = 0.f;
            GetTotalAppMemSize(cpuMemSize, gpuMemSize);
            if (!reply.WriteFloat(cpuMemSize) || !reply.WriteFloat(gpuMemSize)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_CAPABILITY): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSScreenCapability screenCapability = GetScreenCapability(id);
            if (!reply.WriteParcelable(&screenCapability)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_POWER_STATUS): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ScreenPowerStatus status = GetScreenPowerStatus(id);
            if (!reply.WriteUint32(static_cast<uint32_t>(status))) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_DATA): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSScreenData screenData = GetScreenData(id);
            if (!reply.WriteParcelable(&screenData)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_BACK_LIGHT): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t level = GetScreenBacklight(id);
            if (!reply.WriteInt32(level)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_BACK_LIGHT): {
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t level{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(level)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetScreenBacklight(id, level);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_AVAILABLE_LISTENER): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!accessible && (ExtractPid(id) != callingPid)) {
                RS_LOGW("The SetBufferAvailableListener isn't legal, nodeId:%{public}" PRIu64 ", callingPid:%{public}d",
                    id, callingPid);
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            auto remoteObject = data.ReadRemoteObject();
            bool isFromRenderThread = data.ReadBool();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIBufferAvailableCallback> cb = iface_cast<RSIBufferAvailableCallback>(remoteObject);
            if (cb == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            RegisterBufferAvailableListener(id, cb, isFromRenderThread);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_CLEAR_LISTENER): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!accessible && (ExtractPid(id) != callingPid)) {
                RS_LOGW("The SetBufferClearListener isn't legal, nodeId:%{public}" PRIu64 ", callingPid:%{public}d",
                    id, callingPid);
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIBufferClearCallback> cb = iface_cast<RSIBufferClearCallback>(remoteObject);
            if (cb == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            RegisterBufferClearListener(id, cb);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_GAMUTS): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::vector<uint32_t> modeSend;
            std::vector<ScreenColorGamut> mode;
            int32_t result = GetScreenSupportedColorGamuts(id, mode);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                ret = ERR_UNKNOWN_REASON;
                break;
            }
            std::copy(mode.begin(), mode.end(), std::back_inserter(modeSend));
            if (!reply.WriteUInt32Vector(modeSend)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_METADATAKEYS): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::vector<uint32_t> keySend;
            std::vector<ScreenHDRMetadataKey> keys;
            int32_t result = GetScreenSupportedMetaDataKeys(id, keys);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                ret = ERR_UNKNOWN_REASON;
                break;
            }
            for (auto i : keys) {
                keySend.push_back(i);
            }
            if (!reply.WriteUInt32Vector(keySend)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_GAMUT): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ScreenColorGamut mode;
            int32_t result = GetScreenColorGamut(id, mode);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                ret = ERR_UNKNOWN_REASON;
                break;
            }
            if (!reply.WriteUint32(mode)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_GAMUT): {
            ScreenId id{INVALID_SCREEN_ID};
            int32_t modeIdx{0};
            if (!data.ReadUint64(id) || !data.ReadInt32(modeIdx)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t result = SetScreenColorGamut(id, modeIdx);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_GAMUT_MAP): {
            ScreenId id{INVALID_SCREEN_ID};
            int32_t mode{0};
            if (!data.ReadUint64(id) || !data.ReadInt32(mode)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t result = SetScreenGamutMap(id, static_cast<ScreenGamutMap>(mode));
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_CORRECTION): {
            ScreenId id{INVALID_SCREEN_ID};
            int32_t screenRotation{0};
            if (!data.ReadUint64(id) || !data.ReadInt32(screenRotation)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t result = SetScreenCorrection(id, static_cast<ScreenRotation>(screenRotation));
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_MIRROR_SCREEN_CANVAS_ROTATION): {
            ScreenId id{INVALID_SCREEN_ID};
            bool canvasRotation{false};
            if (!data.ReadUint64(id) || !data.ReadBool(canvasRotation)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool result = SetVirtualMirrorScreenCanvasRotation(id, canvasRotation);
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_MIRROR_SCREEN_SCALE_MODE): {
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t scaleMode{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(scaleMode)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool result = SetVirtualMirrorScreenScaleMode(id, static_cast<ScreenScaleMode>(scaleMode));
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_GLOBAL_DARK_COLOR_MODE): {
            bool isDark{false};
            if (!data.ReadBool(isDark)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool result = SetGlobalDarkColorMode(isDark);
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_GAMUT_MAP): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ScreenGamutMap mode;
            int32_t result = GetScreenGamutMap(id, mode);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                ret = ERR_UNKNOWN_REASON;
                break;
            }
            if (!reply.WriteUint32(mode)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_VSYNC_CONNECTION): {
            std::string name = data.ReadString();
            auto remoteObj = data.ReadRemoteObject();
            uint64_t id = data.ReadUint64();
            NodeId windowNodeID = data.ReadUint64();
            if (remoteObj == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            if (!remoteObj->IsProxyObject()) {
                ret = ERR_UNKNOWN_OBJECT;
                break;
            }
            auto token = iface_cast<VSyncIConnectionToken>(remoteObj);
            if (token == nullptr) {
                ret = ERR_UNKNOWN_OBJECT;
                break;
            }
            sptr<IVSyncConnection> conn = CreateVSyncConnection(name, token, id, windowNodeID);
            if (conn == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
#ifdef ENABLE_IPC_SECURITY_ACCESS_COUNTER
            securityUtils_.IncreaseAccessCounter(code);
#endif
            if (!reply.WriteRemoteObject(conn->AsObject())) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_PIXEL_MAP_FROM_SURFACE): {
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                if (!reply.WriteInt32(0)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
                ret = ERR_NULL_OBJECT;
                break;
            }
            auto bufferProducer = iface_cast<IBufferProducer>(remoteObject);
            sptr<Surface> surface = Surface::CreateSurfaceAsProducer(bufferProducer);
            if (surface == nullptr) {
                if (!reply.WriteInt32(0)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t x = 0;
            int32_t y = 0;
            int32_t w = 0;
            int32_t h = 0;
            if (!data.ReadInt32(x) || !data.ReadInt32(y) || !data.ReadInt32(w) || !data.ReadInt32(h)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            auto srcRect = Rect {
                .x = x,
                .y = y,
                .w = w,
                .h = h
            };
            std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMapFromSurface(surface, srcRect);
            if (pixelMap) {
                if (!reply.WriteBool(true)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
                if (!pixelMap->Marshalling(reply)) {
                    RS_LOGE("pixelMap Marshalling fail");
                    ret = ERR_INVALID_REPLY;
                }
            } else {
                if (!reply.WriteBool(false)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_HDR_CAPABILITY): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSScreenHDRCapability screenHDRCapability;
            int32_t result = GetScreenHDRCapability(id, screenHDRCapability);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                ret = ERR_UNKNOWN_REASON;
                break;
            }
            if (!reply.WriteParcelable(&screenHDRCapability)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_PIXEL_FORMAT): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            GraphicPixelFormat pixelFormat;
            int32_t result = GetPixelFormat(id, pixelFormat);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                break;
            }
            if (!reply.WriteUint32(static_cast<uint32_t>(pixelFormat))) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_PIXEL_FORMAT): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            GraphicPixelFormat pixelFormat = static_cast<GraphicPixelFormat>(data.ReadInt32());
            int32_t result = SetPixelFormat(id, pixelFormat);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_HDR_FORMATS): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::vector<uint32_t> hdrFormatsSend;
            std::vector<ScreenHDRFormat> hdrFormats;
            int32_t result = GetScreenSupportedHDRFormats(id, hdrFormats);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                break;
            }
            std::copy(hdrFormats.begin(), hdrFormats.end(), std::back_inserter(hdrFormatsSend));
            if (!reply.WriteUInt32Vector(hdrFormatsSend)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_HDR_FORMAT): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ScreenHDRFormat hdrFormat;
            int32_t result = GetScreenHDRFormat(id, hdrFormat);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                break;
            }
            if (!reply.WriteUint32(hdrFormat)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_HDR_FORMAT): {
            ScreenId id{INVALID_SCREEN_ID};
            int32_t modeIdx{0};
            if (!data.ReadUint64(id) || !data.ReadInt32(modeIdx)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t result = SetScreenHDRFormat(id, modeIdx);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_COLORSPACES): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            std::vector<uint32_t> colorSpacesSend;
            std::vector<GraphicCM_ColorSpaceType> colorSpaces;
            int32_t result = GetScreenSupportedColorSpaces(id, colorSpaces);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                break;
            }
            std::copy(colorSpaces.begin(), colorSpaces.end(), std::back_inserter(colorSpacesSend));
            if (!reply.WriteUInt32Vector(colorSpacesSend)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_COLORSPACE): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            GraphicCM_ColorSpaceType colorSpace;
            int32_t result = GetScreenColorSpace(id, colorSpace);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                break;
            }
            if (!reply.WriteUint32(colorSpace)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_COLORSPACE): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            GraphicCM_ColorSpaceType colorSpace = static_cast<GraphicCM_ColorSpaceType>(data.ReadInt32());
            int32_t result = SetScreenColorSpace(id, colorSpace);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_TYPE): {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSScreenType type;
            int32_t result = GetScreenType(id, type);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result != StatusCode::SUCCESS) {
                ret = ERR_UNKNOWN_REASON;
                break;
            }
            if (!reply.WriteUint32(type)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_BITMAP): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!IsValidCallingPid(ExtractPid(id), callingPid)) {
                RS_LOGW("The GetBitmap isn't legal, nodeId:%{public}" PRIu64 ", callingPid:%{public}d",
                    id, callingPid);
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            Drawing::Bitmap bm;
            bool result = GetBitmap(id, bm);
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result) {
                RSMarshallingHelper::Marshalling(reply, bm);
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_PIXELMAP): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!IsValidCallingPid(ExtractPid(id), callingPid)) {
                RS_LOGW("The GetPixelmap isn't legal, nodeId:%{public}" PRIu64 ", callingPid:%{public}d",
                    id, callingPid);
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            std::shared_ptr<Media::PixelMap> pixelmap =
                std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
            Drawing::Rect rect;
            RSMarshallingHelper::Unmarshalling(data, rect);
            std::shared_ptr<Drawing::DrawCmdList> drawCmdList;
            RSMarshallingHelper::Unmarshalling(data, drawCmdList);
            bool result = GetPixelmap(id, pixelmap, &rect, drawCmdList);
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            if (result) {
                RSMarshallingHelper::Marshalling(reply, pixelmap);
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NEED_REGISTER_TYPEFACE): {
            bool result = false;
            uint64_t uniqueId = data.ReadUint64();
            uint32_t hash = data.ReadUint32();
            RS_PROFILER_PATCH_TYPEFACE_GLOBALID(data, uniqueId);
            if (IsValidCallingPid(ExtractPid(uniqueId), callingPid)) {
                result = !RSTypefaceCache::Instance().HasTypeface(uniqueId, hash);
            } else {
                RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest callingPid[%{public}d] "
                        "no permission NEED_REGISTER_TYPEFACE", callingPid);
            }
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_TYPEFACE): {
            // timer: 3s
            OHOS::Rosen::RSXCollie registerTypefaceXCollie("registerTypefaceXCollie_" + std::to_string(callingPid), 3);
            bool result = false;
            uint64_t uniqueId = data.ReadUint64();
            uint32_t hash = data.ReadUint32();
            // safe check
            if (IsValidCallingPid(ExtractPid(uniqueId), callingPid)) {
                std::shared_ptr<Drawing::Typeface> typeface;
                result = RSMarshallingHelper::Unmarshalling(data, typeface);
                if (result && typeface) {
                    typeface->SetHash(hash);
                    RS_PROFILER_PATCH_TYPEFACE_GLOBALID(data, uniqueId);
                    RegisterTypeface(uniqueId, typeface);
                }
            } else {
                RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest callingPid[%{public}d] "
                    "no permission REGISTER_TYPEFACE", callingPid);
            }
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_TYPEFACE): {
            uint64_t uniqueId = data.ReadUint64();
            // safe check
            if (IsValidCallingPid(ExtractPid(uniqueId), callingPid)) {
                RS_PROFILER_PATCH_TYPEFACE_GLOBALID(data, uniqueId);
                UnRegisterTypeface(uniqueId);
            } else {
                RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest callingPid[%{public}d] "
                    "no permission UNREGISTER_TYPEFACE", callingPid);
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_SKIP_FRAME_INTERVAL): {
            if (!securityManager_.IsInterfaceCodeAccessible(code)) {
                RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest no permission to access"\
                    "SET_SCREEN_SKIP_FRAME_INTERVAL");
                return ERR_INVALID_STATE;
            }
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t skipFrameInterval{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(skipFrameInterval)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t result = SetScreenSkipFrameInterval(id, skipFrameInterval);
            if (!reply.WriteInt32(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_REFRESH_RATE): {
            ScreenId id = 0;
            uint32_t maxRefreshRate = 0;
            if (!data.ReadUint64(id) || !data.ReadUint32(maxRefreshRate)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            uint32_t actualRefreshRate = 0;
            int32_t result = SetVirtualScreenRefreshRate(id, maxRefreshRate, actualRefreshRate);
            if (!reply.WriteInt32(result)) {
                return ERR_INVALID_REPLY;
            }
            if (!reply.WriteUint32(actualRefreshRate)) {
                return ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_ACTIVE_RECT): {
            ScreenId id{INVALID_SCREEN_ID};
            int32_t x{0};
            int32_t y{0};
            int32_t w{0};
            int32_t h{0};
            if (!data.ReadUint64(id) || !data.ReadInt32(x) || !data.ReadInt32(y) ||
                !data.ReadInt32(w) || !data.ReadInt32(h)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            Rect activeRect {
                .x = x,
                .y = y,
                .w = w,
                .h = h
            };
            uint32_t result = SetScreenActiveRect(id, activeRect);
            if (!reply.WriteUint32(result)) {
                return ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_OCCLUSION_CHANGE_CALLBACK): {
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIOcclusionChangeCallback> callback = iface_cast<RSIOcclusionChangeCallback>(remoteObject);
            if (callback == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = RegisterOcclusionChangeCallback(callback);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::REGISTER_SURFACE_OCCLUSION_CHANGE_CALLBACK): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            if (!IsValidCallingPid(ExtractPid(id), callingPid)) {
                RS_LOGW("The RegisterSurfaceOcclusionChangeCallback isn't legal, nodeId:%{public}" PRIu64 ", "
                    "callingPid:%{public}d", id, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSISurfaceOcclusionChangeCallback> callback =
                iface_cast<RSISurfaceOcclusionChangeCallback>(remoteObject);
            if (callback == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            std::vector<float> partitionPoints;
            if (!data.ReadFloatVector(&partitionPoints)) {
                ret = ERR_TRANSACTION_FAILED;
                break;
            }
            int32_t status = RegisterSurfaceOcclusionChangeCallback(id, callback, partitionPoints);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::UNREGISTER_SURFACE_OCCLUSION_CHANGE_CALLBACK): {
            NodeId id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RS_PROFILER_PATCH_NODE_ID(data, id);
            if (!IsValidCallingPid(ExtractPid(id), callingPid)) {
                RS_LOGW("The UnRegisterSurfaceOcclusionChangeCallback isn't legal, nodeId:%{public}" PRIu64 ", "
                    "callingPid:%{public}d", id, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = UnRegisterSurfaceOcclusionChangeCallback(id);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_APP_WINDOW_NUM): {
            uint32_t num{0};
            if (!data.ReadUint32(num)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetAppWindowNum(num);
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::SET_SYSTEM_ANIMATED_SCENES): {
            uint32_t systemAnimatedScenes{0};
            if (!data.ReadUint32(systemAnimatedScenes)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool result = SetSystemAnimatedScenes(static_cast<SystemAnimatedScenes>(systemAnimatedScenes));
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_WATERMARK): {
            if (!RSSystemProperties::GetSurfaceNodeWatermarkEnabled()) {
                RS_LOGI("Current disenable water mark");
                break;
            }
            std::string name;
            if (!data.ReadString(name)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            auto watermark = std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
            if (watermark == nullptr) {
                ret = ERR_NULL_OBJECT;
                RS_LOGE("RSRenderServiceConnectionStub::std::shared_ptr<Media::PixelMap> watermark == nullptr");
                break;
            }
            SetWatermark(name, watermark);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SHOW_WATERMARK): {
            std::shared_ptr<Media::PixelMap> watermarkImg =
                std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
            bool isShow{false};
            if (!data.ReadBool(isShow)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ShowWatermark(watermarkImg, isShow);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::RESIZE_VIRTUAL_SCREEN): {
            ScreenId id{INVALID_SCREEN_ID};
            uint32_t width{0};
            uint32_t height{0};
            if (!data.ReadUint64(id) || !data.ReadUint32(width) || !data.ReadUint32(height)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            int32_t status = ResizeVirtualScreen(id, width, height);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_JANK_STATS): {
            ReportJankStats();
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_RESPONSE): {
            DataBaseRs info;
            if (!ReadDataBaseRs(info, data)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ReportEventResponse(info);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_COMPLETE): {
            DataBaseRs info;
            if (!ReadDataBaseRs(info, data)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ReportEventComplete(info);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_JANK_FRAME): {
            DataBaseRs info;
            if (!ReadDataBaseRs(info, data)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ReportEventJankFrame(info);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_GAMESTATE): {
            GameStateData info;
            if (!ReadGameStateDataRs(info, data)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            ReportGameStateData(info);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::EXECUTE_SYNCHRONOUS_TASK): {
            int16_t type{0};
            int16_t subType{0};
            if (!data.ReadInt16(type) || !data.ReadInt16(subType)) {
                ret = ERR_INVALID_STATE;
                break;
            }
            if (type != RS_NODE_SYNCHRONOUS_READ_PROPERTY && type != RS_NODE_SYNCHRONOUS_GET_VALUE_FRACTION) {
                ret = ERR_INVALID_STATE;
                break;
            }
            auto func = RSCommandFactory::Instance().GetUnmarshallingFunc(type, subType);
            if (func == nullptr) {
                ret = ERR_INVALID_STATE;
                break;
            }
            auto command = static_cast<RSSyncTask*>((*func)(data));
            if (command == nullptr) {
                ret = ERR_INVALID_STATE;
                break;
            }
            std::shared_ptr<RSSyncTask> task(command);
            const auto& nodeMap = RSMainThread::Instance()->GetContext().GetNodeMap();
            if (!task->IsCallingPidValid(callingPid, nodeMap)) {
                ret = ERR_INVALID_STATE;
                break;
            }
            ExecuteSynchronousTask(task);
            if (!task->Marshalling(reply)) {
                ret = ERR_INVALID_STATE;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_HARDWARE_ENABLED) : {
            uint64_t id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!IsValidCallingPid(ExtractPid(id), callingPid)) {
                RS_LOGW("The SetHardwareEnabled isn't legal, nodeId:%{public}" PRIu64 ", callingPid:%{public}d",
                    id, callingPid);
                break;
            }
            bool isEnabled{false};
            uint8_t selfDrawingType{static_cast<uint8_t>(SelfDrawingNodeType::DEFAULT)};
            bool dynamicHardwareEnable{false};
            if (!data.ReadBool(isEnabled) ||
                !data.ReadUint8(selfDrawingType) ||
                !data.ReadBool(dynamicHardwareEnable)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetHardwareEnabled(id, isEnabled, static_cast<SelfDrawingNodeType>(selfDrawingType), dynamicHardwareEnable);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_HIDE_PRIVACY_CONTENT) : {
            uint64_t id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            auto isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
                RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ +
                "::SET_HIDE_PRIVACY_CONTENT");
            if (!isSystemCalling) {
                if (!reply.WriteUint32(static_cast<uint32_t>(RSInterfaceErrorCode::NONSYSTEM_CALLING))) {
                    ret = ERR_INVALID_REPLY;
                }
                break;
            }
            if (ExtractPid(id) != callingPid) {
                RS_LOGW("The SetHidePrivacyContent isn't legal, nodeId:%{public}" PRIu64 ", callingPid:%{public}d",
                    id, callingPid);
                if (!reply.WriteUint32(static_cast<uint32_t>(RSInterfaceErrorCode::NOT_SELF_CALLING))) {
                    ret = ERR_INVALID_REPLY;
                }
                break;
            }
            auto needHidePrivacyContent = data.ReadBool();
            if (!reply.WriteUint32(SetHidePrivacyContent(id, needHidePrivacyContent))) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_LIGHT_FACTOR_STATUS) : {
            bool isSafe{false};
            if (!data.ReadBool(isSafe)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            NotifyLightFactorStatus(isSafe);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_PACKAGE_EVENT) : {
            uint32_t listSize{0};
            if (!data.ReadUint32(listSize)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            const uint32_t MAX_LIST_SIZE = 50;
            if (listSize > MAX_LIST_SIZE) {
                ret = ERR_INVALID_STATE;
                break;
            }
            std::vector<std::string> packageList;
            bool errFlag{false};
            for (uint32_t i = 0; i < listSize; i++) {
                std::string package;
                if (!data.ReadString(package)) {
                    errFlag = true;
                    break;
                }
                packageList.push_back(package);
            }
            if (errFlag) {
                ret = ERR_INVALID_DATA;
                break;
            }
            NotifyPackageEvent(listSize, packageList);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_REFRESH_RATE_EVENT) : {
            std::string eventName;
            bool eventStatus{false};
            uint32_t minRefreshRate{0};
            uint32_t maxRefreshRate{0};
            std::string description;
            if (!data.ReadString(eventName) || !data.ReadBool(eventStatus) || !data.ReadUint32(minRefreshRate) ||
                !data.ReadUint32(maxRefreshRate) || !data.ReadString(description)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            EventInfo eventInfo = {
                eventName, eventStatus, minRefreshRate, maxRefreshRate, description
            };
            NotifyRefreshRateEvent(eventInfo);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_SOFT_VSYNC_EVENT) : {
            uint32_t pid{0};
            uint32_t rateDiscount{0};
            if (!data.ReadUint32(pid) || !data.ReadUint32(rateDiscount)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            NotifySoftVsyncEvent(pid, rateDiscount);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_DYNAMIC_MODE_EVENT) : {
            bool enableDynamicMode{false};
            if (!data.ReadBool(enableDynamicMode)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            NotifyDynamicModeEvent(enableDynamicMode);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_TOUCH_EVENT) : {
            int32_t touchStatus{0};
            int32_t touchCnt{0};
            if (!data.ReadInt32(touchStatus) || !data.ReadInt32(touchCnt)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            NotifyTouchEvent(touchStatus, touchCnt);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_HGM_CFG_CALLBACK) : {
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIHgmConfigChangeCallback> callback = iface_cast<RSIHgmConfigChangeCallback>(remoteObject);
            if (callback == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = RegisterHgmConfigChangeCallback(callback);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REFRESH_RATE_MODE_CHANGE_CALLBACK) : {
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIHgmConfigChangeCallback> callback =
                iface_cast<RSIHgmConfigChangeCallback>(remoteObject);
            if (callback == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = RegisterHgmRefreshRateModeChangeCallback(callback);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REFRESH_RATE_UPDATE_CALLBACK) : {
            sptr<RSIHgmConfigChangeCallback> callback = nullptr;
            sptr<IRemoteObject> remoteObject = nullptr;
            bool readRemoteObject{false};
            if (!data.ReadBool(readRemoteObject)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (readRemoteObject) {
                remoteObject = data.ReadRemoteObject();
            }
            if (remoteObject != nullptr) {
                callback = iface_cast<RSIHgmConfigChangeCallback>(remoteObject);
            }
            int32_t status = RegisterHgmRefreshRateUpdateCallback(callback);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(
            RSIRenderServiceConnectionInterfaceCode::REGISTER_FRAME_RATE_LINKER_EXPECTED_FPS_CALLBACK) : {
            sptr<RSIFrameRateLinkerExpectedFpsUpdateCallback> callback = nullptr;
            sptr<IRemoteObject> remoteObject = nullptr;
            int32_t dstPid{0};
            bool readRemoteObject{false};
            if (!data.ReadInt32(dstPid) || !data.ReadBool(readRemoteObject)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (readRemoteObject) {
                remoteObject = data.ReadRemoteObject();
            }
            if (remoteObject != nullptr) {
                callback = iface_cast<RSIFrameRateLinkerExpectedFpsUpdateCallback>(remoteObject);
            }
            int32_t status = RegisterFrameRateLinkerExpectedFpsUpdateCallback(dstPid, callback);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_ROTATION_CACHE_ENABLED) : {
            bool isEnabled = false;
            if (!data.ReadBool(isEnabled)) {
                ret = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            SetCacheEnabledForRotation(isEnabled);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ACTIVE_DIRTY_REGION_INFO) : {
            const auto& activeDirtyRegionInfos = GetActiveDirtyRegionInfo();
            if (!reply.WriteInt32(activeDirtyRegionInfos.size())) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            for (const auto& activeDirtyRegionInfo : activeDirtyRegionInfos) {
                if (!reply.WriteInt64(activeDirtyRegionInfo.activeDirtyRegionArea) ||
                    !reply.WriteInt32(activeDirtyRegionInfo.activeFramesNumber) ||
                    !reply.WriteInt32(activeDirtyRegionInfo.pidOfBelongsApp) ||
                    !reply.WriteString(activeDirtyRegionInfo.windowName)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_GLOBAL_DIRTY_REGION_INFO) : {
            const auto& globalDirtyRegionInfo = GetGlobalDirtyRegionInfo();
            if (!reply.WriteInt64(globalDirtyRegionInfo.globalDirtyRegionAreas) ||
                !reply.WriteInt32(globalDirtyRegionInfo.globalFramesNumber) ||
                !reply.WriteInt32(globalDirtyRegionInfo.skipProcessFramesNumber) ||
                !reply.WriteInt32(globalDirtyRegionInfo.mostSendingPidWhenDisplayNodeSkip)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_LAYER_COMPOSE_INFO) : {
            const auto& LayerComposeInfo = GetLayerComposeInfo();
            if (!reply.WriteInt32(LayerComposeInfo.uniformRenderFrameNumber) ||
                !reply.WriteInt32(LayerComposeInfo.offlineComposeFrameNumber) ||
                !reply.WriteInt32(LayerComposeInfo.redrawFrameNumber)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::
            GET_HARDWARE_COMPOSE_DISABLED_REASON_INFO) : {
            const auto& hwcDisabledReasonInfos = GetHwcDisabledReasonInfo();
            if (!reply.WriteInt32(hwcDisabledReasonInfos.size())) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            for (const auto& hwcDisabledReasonInfo : hwcDisabledReasonInfos) {
                for (const auto& disabledReasonCount : hwcDisabledReasonInfo.disabledReasonStatistics) {
                    if (!reply.WriteInt32(disabledReasonCount)) {
                        ret = ERR_INVALID_REPLY;
                        break;
                    }
                }
                if (ret == ERR_INVALID_REPLY) {
                    break;
                }
                if (!reply.WriteInt32(hwcDisabledReasonInfo.pidOfBelongsApp) ||
                    !reply.WriteString(hwcDisabledReasonInfo.nodeName)) {
                    ret = ERR_INVALID_REPLY;
                    break;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_HDR_ON_DURATION) : {
            int64_t hdrOnDuration = GetHdrOnDuration();
            if (!reply.WriteInt64(hdrOnDuration)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
#ifdef TP_FEATURE_ENABLE
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_TP_FEATURE_CONFIG) : {
            int32_t feature{0};
            if (!data.ReadInt32(feature)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            auto config = data.ReadCString();
            if (config == nullptr) {
                ret = ERR_INVALID_DATA;
                break;
            }
            uint8_t tpFeatureConfigType{0};
            if (!data.ReadUint8(tpFeatureConfigType)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetTpFeatureConfig(feature, config, static_cast<TpFeatureConfigType>(tpFeatureConfigType));
            break;
        }
#endif
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_USING_STATUS) : {
            bool isVirtualScreenUsingStatus{false};
            if (!data.ReadBool(isVirtualScreenUsingStatus)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetVirtualScreenUsingStatus(isVirtualScreenUsingStatus);
            break;
        }

        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_CURTAIN_SCREEN_USING_STATUS) : {
            bool isCurtainScreenOn{false};
            if (!data.ReadBool(isCurtainScreenOn)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetCurtainScreenUsingStatus(isCurtainScreenOn);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::DROP_FRAME_BY_PID) : {
            std::vector<int32_t> pidList;
            if (!data.ReadInt32Vector(&pidList)) {
                ret = ERR_INVALID_REPLY;
                break;
            }
            DropFrameByPid(pidList);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_UIEXTENSION_CALLBACK): {
            uint64_t userId{0};
            if (!data.ReadUint64(userId)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            sptr<RSIUIExtensionCallback> callback = iface_cast<RSIUIExtensionCallback>(remoteObject);
            if (callback == nullptr) {
                ret = ERR_NULL_OBJECT;
                break;
            }
            int32_t status = RegisterUIExtensionCallback(userId, callback);
            if (!reply.WriteInt32(status)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_STATUS) : {
            ScreenId id{INVALID_SCREEN_ID};
            uint8_t screenStatus{0};
            if (!data.ReadUint64(id) || !data.ReadUint8(screenStatus)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool result = SetVirtualScreenStatus(id, static_cast<VirtualScreenStatus>(screenStatus));
            if (!reply.WriteBool(result)) {
                ret = ERR_INVALID_REPLY;
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VMA_CACHE_STATUS) : {
            bool flag = data.ReadBool();
            SetVmaCacheStatus(flag);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_ANCO_FORCE_DO_DIRECT) : {
            bool direct{false};
            if (!data.ReadBool(direct)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool result = SetAncoForceDoDirect(direct);
            reply.WriteBool(result);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_DISPLAY_NODE) : {
            uint64_t id{0};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            bool isNonSystemCalling = false;
            bool isTokenTypeValid = true;
            RSInterfaceCodeAccessVerifierBase::GetAccessType(isTokenTypeValid, isNonSystemCalling);
            if (isNonSystemCalling && !IsValidCallingPid(ExtractPid(id), callingPid)) {
                RS_LOGW("CREATE_DISPLAY_NODE invalid nodeId[%{public}" PRIu64 "] pid[%{public}d]", id, callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            uint64_t mirrorId{0};
            uint64_t screenId{0};
            bool isMirrored{false};
            if (!data.ReadUint64(mirrorId) ||
                !data.ReadUint64(screenId) ||
                !data.ReadBool(isMirrored)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            RSDisplayNodeConfig config = {
                .screenId = screenId,
                .isMirrored = isMirrored,
                .mirrorNodeId = mirrorId,
                .isSync = true,
            };
            reply.WriteBool(CreateNode(config, id));
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_FREE_MULTI_WINDOW_STATUS) : {
            bool enable{false};
            if (!data.ReadBool(enable)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetFreeMultiWindowStatus(enable);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_SURFACE_BUFFER_CALLBACK) : {
            int32_t pid{0};
            uint64_t uid{0};
            if (!data.ReadInt32(pid) ||
                !data.ReadUint64(uid)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!IsValidCallingPid(pid, callingPid)) {
                RS_LOGW("REGISTER_SURFACE_BUFFER_CALLBACK invalid pid[%{public}d]", callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            auto remoteObject = data.ReadRemoteObject();
            if (remoteObject == nullptr) {
                ret = ERR_NULL_OBJECT;
                RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest remoteObject == nullptr");
                break;
            }
            sptr<RSISurfaceBufferCallback> callback = iface_cast<RSISurfaceBufferCallback>(remoteObject);
            if (callback == nullptr) {
                ret = ERR_NULL_OBJECT;
                RS_LOGE("RSRenderServiceConnectionStub::OnRemoteRequest remoteObject cast error");
                break;
            }
            RegisterSurfaceBufferCallback(pid, uid, callback);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_SURFACE_BUFFER_CALLBACK) : {
            int32_t pid{0};
            uint64_t uid{0};
            if (!data.ReadInt32(pid) ||
                !data.ReadUint64(uid)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            if (!IsValidCallingPid(pid, callingPid)) {
                RS_LOGW("UNREGISTER_SURFACE_BUFFER_CALLBACK invalid pid[%{public}d]", callingPid);
                ret = ERR_INVALID_DATA;
                break;
            }
            UnregisterSurfaceBufferCallback(pid, uid);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_LAYER_TOP) : {
            std::string nodeIdStr;
            bool isTop{false};
            if (!data.ReadString(nodeIdStr) ||
                !data.ReadBool(isTop)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            SetLayerTop(nodeIdStr, isTop);
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_SCREEN_SWITCHED) : {
            ScreenId id{INVALID_SCREEN_ID};
            if (!data.ReadUint64(id)) {
                ret = ERR_INVALID_DATA;
                break;
            }
            NotifyScreenSwitched(id);
            break;
        }
        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }

    return ret;
}

bool RSRenderServiceConnectionStub::ReadDataBaseRs(DataBaseRs& info, MessageParcel& data)
{
    if (!data.ReadInt32(info.appPid) || !data.ReadInt32(info.eventType) ||
        !data.ReadInt32(info.versionCode) || !data.ReadInt64(info.uniqueId) ||
        !data.ReadInt64(info.inputTime) || !data.ReadInt64(info.beginVsyncTime) ||
        !data.ReadInt64(info.endVsyncTime) || !data.ReadBool(info.isDisplayAnimator) ||
        !data.ReadString(info.sceneId) || !data.ReadString(info.versionName) ||
        !data.ReadString(info.bundleName) || !data.ReadString(info.processName) ||
        !data.ReadString(info.abilityName) ||!data.ReadString(info.pageUrl) ||
        !data.ReadString(info.sourceType) || !data.ReadString(info.note)) {
        return false;
    }
    return true;
}

bool RSRenderServiceConnectionStub::ReadGameStateDataRs(GameStateData& info, MessageParcel& data)
{
    if (!data.ReadInt32(info.pid) || !data.ReadInt32(info.uid) ||
        !data.ReadInt32(info.state) || !data.ReadInt32(info.renderTid) ||
        !data.ReadString(info.bundleName)) {
        return false;
    }
    return true;
}

bool RSRenderServiceConnectionStub::ReadSurfaceCaptureConfig(RSSurfaceCaptureConfig& captureConfig, MessageParcel& data)
{
    uint8_t captureType { 0 };
    if (!data.ReadFloat(captureConfig.scaleX) || !data.ReadFloat(captureConfig.scaleY) ||
        !data.ReadBool(captureConfig.useDma) || !data.ReadBool(captureConfig.useCurWindow) ||
        !data.ReadUint8(captureType) || !data.ReadBool(captureConfig.isSync) ||
        !data.ReadFloat(captureConfig.mainScreenRect.left_) ||
        !data.ReadFloat(captureConfig.mainScreenRect.top_) ||
        !data.ReadFloat(captureConfig.mainScreenRect.right_) ||
        !data.ReadFloat(captureConfig.mainScreenRect.bottom_)) {
        return false;
    }
    captureConfig.captureType = static_cast<SurfaceCaptureType>(captureType);
    return true;
}

bool RSRenderServiceConnectionStub::ReadSurfaceCaptureBlurParam(
    RSSurfaceCaptureBlurParam& blurParam, MessageParcel& data)
{
    if (!data.ReadBool(blurParam.isNeedBlur) || !data.ReadFloat(blurParam.blurRadius)) {
        return false;
    }
    return true;
}

const RSInterfaceCodeSecurityManager RSRenderServiceConnectionStub::securityManager_ = \
    RSInterfaceCodeSecurityManager::CreateInstance<RSIRenderServiceConnectionInterfaceCodeAccessVerifier>();
} // namespace Rosen
} // namespace OHOS
