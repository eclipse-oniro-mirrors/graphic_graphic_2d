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

#include "rs_render_service_connection_proxy.h"

#include <algorithm>
#include <cstdint>
#include <message_option.h>
#include <message_parcel.h>
#include <vector>
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "transaction/rs_ashmem_helper.h"
#include "transaction/rs_marshalling_helper.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {
namespace {
static constexpr size_t ASHMEM_SIZE_THRESHOLD = 400 * 1024; // cannot > 500K in TF_ASYNC mode
static constexpr int MAX_RETRY_COUNT = 10;
static constexpr int RETRY_WAIT_TIME_US = 500; // wait 0.5ms before retry SendRequest
}

RSRenderServiceConnectionProxy::RSRenderServiceConnectionProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<RSIRenderServiceConnection>(impl)
{
}

void RSRenderServiceConnectionProxy::CommitTransaction(std::unique_ptr<RSTransactionData>& transactionData)
{
    if (!transactionData) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CommitTransaction transactionData nullptr!");
        return;
    }
    bool isUniMode = RSSystemProperties::GetUniRenderEnabled();
    transactionData->SetSendingPid(pid_);

    // split to several parcels if parcel size > PARCEL_SPLIT_THRESHOLD during marshalling
    std::vector<std::shared_ptr<MessageParcel>> parcelVector;
    auto func = [isUniMode, &parcelVector, &transactionData, this]() -> bool {
        if (isUniMode) {
            ++transactionDataIndex_;
        }
        transactionData->SetIndex(transactionDataIndex_);
        std::shared_ptr<MessageParcel> parcel = std::make_shared<MessageParcel>();
        if (!FillParcelWithTransactionData(transactionData, parcel)) {
            ROSEN_LOGE("FillParcelWithTransactionData failed!");
            return false;
        }
        parcelVector.emplace_back(parcel);
        return true;
    };
    if (transactionData->IsNeedSync() && transactionData->IsEmpty()) {
        RS_TRACE_NAME("Commit empty syncTransaction");
        func();
    } else {
        while (transactionData->GetMarshallingIndex() < transactionData->GetCommandCount()) {
            if (!func()) {
                return;
            }
        }
    }

    MessageOption option;
    option.SetFlags(MessageOption::TF_ASYNC);
    for (const auto& parcel : parcelVector) {
        MessageParcel reply;
        uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::COMMIT_TRANSACTION);
        int retryCount = 0;
        int32_t err = NO_ERROR;
        do {
            err = Remote()->SendRequest(code, *parcel, reply, option);
            if (err != NO_ERROR && retryCount < MAX_RETRY_COUNT) {
                retryCount++;
                usleep(RETRY_WAIT_TIME_US);
            } else if (err != NO_ERROR) {
                ROSEN_LOGE("RSRenderServiceConnectionProxy::CommitTransaction SendRequest failed, "
                    "err = %{public}d, retryCount = %{public}d", err, retryCount);
                return;
            }
        } while (err != NO_ERROR && retryCount < MAX_RETRY_COUNT);
    }
}

void RSRenderServiceConnectionProxy::ExecuteSynchronousTask(const std::shared_ptr<RSSyncTask>& task)
{
    if (task == nullptr) {
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSRenderServiceConnectionProxy::GetDescriptor())) {
        return;
    }
    if (!task->Marshalling(data)) {
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::EXECUTE_SYNCHRONOUS_TASK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }

    if (task->CheckHeader(reply)) {
        task->ReadFromParcel(reply);
    }
}

bool RSRenderServiceConnectionProxy::FillParcelWithTransactionData(
    std::unique_ptr<RSTransactionData>& transactionData, std::shared_ptr<MessageParcel>& data)
{
    // write a flag at the begin of parcel to identify parcel type
    // 0: indicate normal parcel
    // 1: indicate ashmem parcel
    if (!data->WriteInt32(0)) {
        return false;
    }

    // 1. marshalling RSTransactionData
    RS_TRACE_BEGIN("MarshRSTransactionData cmdCount:" + std::to_string(transactionData->GetCommandCount()) +
        " transactionFlag:[" + std::to_string(pid_) + "," + std::to_string(transactionData->GetIndex()) + "]");
    ROSEN_LOGI_IF(DEBUG_PIPELINE,
        "MarshRSTransactionData cmdCount:%{public}lu transactionFlag:[pid:%{public}d index:%{public}" PRIu64 "]",
        transactionData->GetCommandCount(), pid_, transactionData->GetIndex());
    bool success = data->WriteParcelable(transactionData.get());
    RS_TRACE_END();
    if (!success) {
        ROSEN_LOGE("FillParcelWithTransactionData data.WriteParcelable failed!");
        return false;
    }

    // 2. convert data to new ashmem parcel if size over threshold
    std::shared_ptr<MessageParcel> ashmemParcel = nullptr;
    if (data->GetDataSize() > ASHMEM_SIZE_THRESHOLD) {
        ashmemParcel = RSAshmemHelper::CreateAshmemParcel(data);
    }
    if (ashmemParcel != nullptr) {
        data = ashmemParcel;
    }
    return true;
}

bool RSRenderServiceConnectionProxy::GetUniRenderEnabled()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_UNI_RENDER_ENABLED);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    return reply.ReadBool();
}

bool RSRenderServiceConnectionProxy::CreateNode(const RSDisplayNodeConfig& displayNodeConfig, NodeId nodeId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreateNode: WriteInterfaceToken err.");
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint64(nodeId)) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreateNode: WriteUint64 NodeId err.");
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint64(displayNodeConfig.mirrorNodeId)) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreateNode: WriteUint64 Config.MirrorNodeId err.");
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint64(displayNodeConfig.screenId)) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreateNode: WriteUint64 Config.ScreenId err.");
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteBool(displayNodeConfig.isMirrored)) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreateNode: WriteBool Config.IsMirrored err.");
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_DISPLAY_NODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }

    return reply.ReadBool();
}

bool RSRenderServiceConnectionProxy::CreateNode(const RSSurfaceRenderNodeConfig& config)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteUint64(config.id)) {
        return false;
    }
    if (!data.WriteString(config.name)) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_NODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }

    return reply.ReadBool();
}

sptr<Surface> RSRenderServiceConnectionProxy::CreateNodeAndSurface(const RSSurfaceRenderNodeConfig& config)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteUint64(config.id)) {
        return nullptr;
    }
    if (!data.WriteString(config.name)) {
        return nullptr;
    }
    if (!data.WriteUint8(static_cast<uint8_t>(config.nodeType))) {
        return nullptr;
    }
    if (!data.WriteBool(config.isTextureExportNode)) {
        return nullptr;
    }
    if (!data.WriteBool(config.isSync)) {
        return nullptr;
    }
    if (!data.WriteUint8(static_cast<uint8_t>(config.surfaceWindowType))) {
        return nullptr;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_NODE_AND_SURFACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return nullptr;
    }
    sptr<IRemoteObject> surfaceObject = reply.ReadRemoteObject();
    sptr<IBufferProducer> bp = iface_cast<IBufferProducer>(surfaceObject);
    if (bp == nullptr) {
        return nullptr;
    }
    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(bp);
    return surface;
}

sptr<IVSyncConnection> RSRenderServiceConnectionProxy::CreateVSyncConnection(const std::string& name,
                                                                             const sptr<VSyncIConnectionToken>& token,
                                                                             uint64_t id,
                                                                             NodeId windowNodeId)
{
    if (token == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreateVSyncConnection: token is nullptr.");
        return nullptr;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteString(name)) {
        return nullptr;
    }
    if (!data.WriteRemoteObject(token->AsObject())) {
        return nullptr;
    }
    if (!data.WriteUint64(id)) {
        return nullptr;
    }
    if (!data.WriteUint64(windowNodeId)) {
        return nullptr;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_VSYNC_CONNECTION);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return nullptr;
    }

    sptr<IRemoteObject> rObj = reply.ReadRemoteObject();
    if (rObj == nullptr) {
        return nullptr;
    }
    sptr<IVSyncConnection> conn = iface_cast<IVSyncConnection>(rObj);
    return conn;
}

std::shared_ptr<Media::PixelMap> RSRenderServiceConnectionProxy::CreatePixelMapFromSurface(sptr<Surface> surface,
    const Rect &srcRect)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (surface == nullptr) {
        return nullptr;
    }

    auto producer = surface->GetProducer();
    if (producer == nullptr) {
        return nullptr;
    }

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return nullptr;
    }
    if (!data.WriteRemoteObject(producer->AsObject())) {
        return nullptr;
    }
    if (!data.WriteInt32(srcRect.x) || !data.WriteInt32(srcRect.y) ||
        !data.WriteInt32(srcRect.w) || !data.WriteInt32(srcRect.h)) {
        return nullptr;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_PIXEL_MAP_FROM_SURFACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::CreatePixelMapFromSurface: Send Request err.");
        return nullptr;
    }

    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    if (reply.ReadBool()) {
        pixelMap.reset(Media::PixelMap::Unmarshalling(reply));
    }
    return pixelMap;
}

int32_t RSRenderServiceConnectionProxy::SetFocusAppInfo(
    int32_t pid, int32_t uid, const std::string &bundleName, const std::string &abilityName, uint64_t focusNodeId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteInt32(pid)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteInt32(uid)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteString(bundleName)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteString(abilityName)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint64(focusNodeId)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_FOCUS_APP_INFO);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetFocusAppInfo: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

ScreenId RSRenderServiceConnectionProxy::GetDefaultScreenId()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return INVALID_SCREEN_ID;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_DEFAULT_SCREEN_ID);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return INVALID_SCREEN_ID;
    }

    ScreenId id = reply.ReadUint64();
    return id;
}

ScreenId RSRenderServiceConnectionProxy::GetActiveScreenId()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return INVALID_SCREEN_ID;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ACTIVE_SCREEN_ID);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return INVALID_SCREEN_ID;
    }

    ScreenId id = reply.ReadUint64();
    return id;
}

std::vector<ScreenId> RSRenderServiceConnectionProxy::GetAllScreenIds()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::vector<ScreenId> screenIds;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return std::vector<ScreenId>();
    }

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ALL_SCREEN_IDS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return std::vector<ScreenId>();
    }

    uint32_t size = reply.ReadUint32();
    size_t readableSize = reply.GetReadableBytes() / sizeof(ScreenId);
    size_t len = static_cast<size_t>(size);
    if (len > readableSize || len > screenIds.max_size()) {
        RS_LOGE("RSRenderServiceConnectionProxy GetAllScreenIds Failed read vector, size:%{public}zu,"
            " readableSize:%{public}zu", len, readableSize);
        return screenIds;
    }
    for (uint32_t i = 0; i < size; i++) {
        screenIds.emplace_back(reply.ReadUint64());
    }

    return screenIds;
}

ScreenId RSRenderServiceConnectionProxy::CreateVirtualScreen(
    const std::string &name,
    uint32_t width,
    uint32_t height,
    sptr<Surface> surface,
    ScreenId mirrorId,
    int32_t flags,
    std::vector<NodeId> whiteList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return INVALID_SCREEN_ID;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    data.WriteString(name);
    data.WriteUint32(width);
    data.WriteUint32(height);

    if (surface==nullptr) {
        data.WriteRemoteObject(nullptr);
    } else {
        auto producer = surface->GetProducer();
        data.WriteRemoteObject(producer->AsObject());
    }

    data.WriteUint64(mirrorId);
    data.WriteInt32(flags);
    data.WriteUInt64Vector(whiteList);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::CREATE_VIRTUAL_SCREEN);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return INVALID_SCREEN_ID;
    }

    ScreenId id = reply.ReadUint64();
    return id;
}

int32_t RSRenderServiceConnectionProxy::SetVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUInt64Vector(blackListVector)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_BLACKLIST);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenBlackList: Send Request err.");
        return RS_CONNECTION_ERROR;
    }

    int32_t status = reply.ReadInt32();
    return status;
}

int32_t RSRenderServiceConnectionProxy::SetVirtualScreenSecurityExemptionList(
    ScreenId id,
    const std::vector<NodeId>& securityExemptionList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUInt64Vector(securityExemptionList)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_SECURITY_EXEMPTION_LIST);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenSecurityExemptionList: Send Request err.");
        return RS_CONNECTION_ERROR;
    }

    int32_t status = reply.ReadInt32();
    return status;
}

int32_t RSRenderServiceConnectionProxy::SetCastScreenEnableSkipWindow(ScreenId id, bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteBool(enable)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_CAST_SCREEN_ENABLE_SKIP_WINDOW);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetCastScreenEnableSkipWindow: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetVirtualScreenSurface(ScreenId id, sptr<Surface> surface)
{
    if (surface == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenSurface: Send surface is nullptr!");
        return INVALID_ARGUMENTS;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    auto producer = surface->GetProducer();
    if (!data.WriteRemoteObject(producer->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_SURFACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenSurface: Send Request err.");
        return RS_CONNECTION_ERROR;
    }

    int32_t status = reply.ReadInt32();
    return status;
}

void RSRenderServiceConnectionProxy::RemoveVirtualScreen(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REMOVE_VIRTUAL_SCREEN);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RemoveVirtualScreen: Send Request err.");
        return;
    }
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t RSRenderServiceConnectionProxy::SetPointerColorInversionConfig(float darkBuffer,
    float brightBuffer, int64_t interval, int32_t rangeSize)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteFloat(darkBuffer)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteFloat(brightBuffer)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteInt64(interval)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteInt32(rangeSize)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_COLOR_INVERSION_CONFIG);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetPointerColorInversionConfig: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}
 
int32_t RSRenderServiceConnectionProxy::SetPointerColorInversionEnabled(bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteBool(enable)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_POINTER_COLOR_INVERSION_ENABLED);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::DisableCursorInvert: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}
 
int32_t RSRenderServiceConnectionProxy::RegisterPointerLuminanceChangeCallback(
    sptr<RSIPointerLuminanceChangeCallback> callback)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterPointerLuminanceChangeCallback: callback is nullptr.");
        return INVALID_ARGUMENTS;
    }
 
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }
 
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_POINTER_LUMINANCE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterPointerLuminanceChangeCallback: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}
 
int32_t RSRenderServiceConnectionProxy::UnRegisterPointerLuminanceChangeCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::UNREGISTER_POINTER_LUMINANCE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::UnRegisterPointerLuminanceChangeCallback: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}
#endif

int32_t RSRenderServiceConnectionProxy::SetScreenChangeCallback(sptr<RSIScreenChangeCallback> callback)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetScreenChangeCallback: callback is nullptr.");
        return INVALID_ARGUMENTS;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_CHANGE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetScreenChangeCallback: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

void RSRenderServiceConnectionProxy::SetScreenActiveMode(ScreenId id, uint32_t modeId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteUint32(modeId)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_ACTIVE_MODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }
}

void RSRenderServiceConnectionProxy::SetScreenRefreshRate(ScreenId id, int32_t sceneId, int32_t rate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteInt32(sceneId)) {
        return;
    }
    if (!data.WriteInt32(rate)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_REFRESH_RATE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return;
    }
}

void RSRenderServiceConnectionProxy::SetRefreshRateMode(int32_t refreshRateMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteInt32(refreshRateMode)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_REFRESH_RATE_MODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return;
    }
}

void RSRenderServiceConnectionProxy::SyncFrameRateRange(FrameRateLinkerId id, const FrameRateRange& range,
    int32_t animatorExpectedFrameRate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteUint32(range.min_) || !data.WriteUint32(range.max_) ||
        !data.WriteUint32(range.preferred_) || !data.WriteUint32(range.type_)) {
        return;
    }
    if (!data.WriteInt32(animatorExpectedFrameRate)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SYNC_FRAME_RATE_RANGE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return;
    }
}
void RSRenderServiceConnectionProxy::UnregisterFrameRateLinker(FrameRateLinkerId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_FRAME_RATE_LINKER);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return;
    }
}

uint32_t RSRenderServiceConnectionProxy::GetScreenCurrentRefreshRate(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return SUCCESS;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return SUCCESS;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_CURRENT_REFRESH_RATE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return SUCCESS;
    }
    uint32_t rate = reply.ReadUint32();
    return rate;
}

int32_t RSRenderServiceConnectionProxy::GetCurrentRefreshRateMode()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return SUCCESS;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_CURRENT_REFRESH_RATE_MODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return SUCCESS;
    }
    int32_t refreshRateMode = reply.ReadInt32();
    return refreshRateMode;
}

std::vector<int32_t> RSRenderServiceConnectionProxy::GetScreenSupportedRefreshRates(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::vector<int32_t> screenSupportedRates;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return screenSupportedRates;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return screenSupportedRates;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_REFRESH_RATES);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return screenSupportedRates;
    }
    uint64_t rateCount = reply.ReadUint64();
    size_t readableSize = reply.GetReadableBytes();
    size_t len = static_cast<size_t>(rateCount);
    if (len > readableSize || len > screenSupportedRates.max_size()) {
        RS_LOGE("RSRenderServiceConnectionProxy GetScreenSupportedRefreshRates "
            "fail read vector, size : %{public}zu, readableSize : %{public}zu", len, readableSize);
        return screenSupportedRates;
    }
    screenSupportedRates.resize(rateCount);
    for (uint64_t rateIndex = 0; rateIndex < rateCount; rateIndex++) {
        screenSupportedRates[rateIndex] = reply.ReadInt32();
    }
    return screenSupportedRates;
}

bool RSRenderServiceConnectionProxy::GetShowRefreshRateEnabled()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return SUCCESS;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SHOW_REFRESH_RATE_ENABLED);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return SUCCESS;
    }
    bool enable = reply.ReadBool();
    return enable;
}

void RSRenderServiceConnectionProxy::SetShowRefreshRateEnabled(bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteBool(enable)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SHOW_REFRESH_RATE_ENABLED);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return;
    }
}

std::string RSRenderServiceConnectionProxy::GetRefreshInfo(pid_t pid)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceProxy failed to get descriptor");
        return "";
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteInt32(pid)) {
        return "";
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_REFRESH_INFO);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy sendrequest error : %{public}d", err);
        return "";
    }
    std::string enable = reply.ReadString();
    return enable;
}

int32_t RSRenderServiceConnectionProxy::SetVirtualScreenResolution(ScreenId id, uint32_t width, uint32_t height)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenResolution: WriteInterfaceToken err.");
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(width)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(height)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_RESOLUTION);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenResolution: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t status = reply.ReadInt32();
    return status;
}

void RSRenderServiceConnectionProxy::MarkPowerOffNeedProcessOneFrame()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::MarkPowerOffNeedProcessOneFrame: Send Request err.");
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code =
        static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::MARK_POWER_OFF_NEED_PROCESS_ONE_FRAME);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }
}

void RSRenderServiceConnectionProxy::DisablePowerOffRenderControl(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::DisablePowerOffRenderControl: Send Request err.");
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::DISABLE_RENDER_CONTROL_SCREEN);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }
}

void RSRenderServiceConnectionProxy::SetScreenPowerStatus(ScreenId id, ScreenPowerStatus status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(status))) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_POWER_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }
}

void RSRenderServiceConnectionProxy::RegisterApplicationAgent(uint32_t pid, sptr<IApplicationAgent> app)
{
    if (app == nullptr) {
        ROSEN_LOGE("RSRenderServiceProxy: callback == nullptr\n");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint32(pid)) {
        return;
    }
    if (!data.WriteRemoteObject(app->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_APPLICATION_AGENT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy: Remote()->SendRequest() error.\n");
        return;
    }
}

void RSRenderServiceConnectionProxy::TakeSurfaceCapture(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig, RSSurfaceCapturePermissions /* permissions */)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceProxy: callback == nullptr\n");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return;
    }
    if (!data.WriteFloat(captureConfig.scaleX) || !data.WriteFloat(captureConfig.scaleY) ||
        !data.WriteBool(captureConfig.useDma) || !data.WriteBool(captureConfig.useCurWindow) ||
        !data.WriteUint8(static_cast<uint8_t>(captureConfig.captureType)) || !data.WriteBool(captureConfig.isSync)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::TAKE_SURFACE_CAPTURE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceProxy: Remote()->SendRequest() error.\n");
        return;
    }
}

RSVirtualScreenResolution RSRenderServiceConnectionProxy::GetVirtualScreenResolution(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    RSVirtualScreenResolution virtualScreenResolution;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return virtualScreenResolution;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return virtualScreenResolution;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_VIRTUAL_SCREEN_RESOLUTION);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return virtualScreenResolution;
    }

    sptr<RSVirtualScreenResolution> pVirtualScreenResolution(reply.ReadParcelable<RSVirtualScreenResolution>());
    if (pVirtualScreenResolution == nullptr) {
        return virtualScreenResolution;
    }
    virtualScreenResolution = *pVirtualScreenResolution;
    return virtualScreenResolution;
}

RSScreenModeInfo RSRenderServiceConnectionProxy::GetScreenActiveMode(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    RSScreenModeInfo screenModeInfo;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return screenModeInfo;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return screenModeInfo;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_ACTIVE_MODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return screenModeInfo;
    }

    sptr<RSScreenModeInfo> pScreenModeInfo(reply.ReadParcelable<RSScreenModeInfo>());
    if (pScreenModeInfo == nullptr) {
        return screenModeInfo;
    }
    screenModeInfo = *pScreenModeInfo;
    return screenModeInfo;
}

std::vector<RSScreenModeInfo> RSRenderServiceConnectionProxy::GetScreenSupportedModes(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::vector<RSScreenModeInfo> screenSupportedModes;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return screenSupportedModes;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return screenSupportedModes;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_MODES);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return screenSupportedModes;
    }

    uint64_t modeCount = reply.ReadUint64();
    size_t readableSize = reply.GetReadableBytes();
    size_t len = static_cast<size_t>(modeCount);
    if (len > readableSize || len > screenSupportedModes.max_size()) {
        RS_LOGE("RSRenderServiceConnectionProxy GetScreenSupportedModes Fail read vector, size:%{public}zu,"
            "readableSize:%{public}zu", len, readableSize);
        return screenSupportedModes;
    }
    screenSupportedModes.resize(modeCount);
    for (uint64_t modeIndex = 0; modeIndex < modeCount; modeIndex++) {
        sptr<RSScreenModeInfo> itemScreenMode = reply.ReadParcelable<RSScreenModeInfo>();
        if (itemScreenMode == nullptr) {
            continue;
        } else {
            screenSupportedModes[modeIndex] = *itemScreenMode;
        }
    }
    return screenSupportedModes;
}

std::vector<MemoryGraphic> RSRenderServiceConnectionProxy::GetMemoryGraphics()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::vector<MemoryGraphic> memoryGraphics;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return memoryGraphics;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHICS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return memoryGraphics;
    }

    uint64_t count = reply.ReadUint64();
    size_t readableSize = reply.GetReadableBytes();
    size_t len = static_cast<size_t>(count);
    if (len > readableSize || len > memoryGraphics.max_size()) {
        RS_LOGE("RSRenderServiceConnectionProxy GetMemoryGraphics Failed to read vector, size:%{public}zu,"
            " readableSize:%{public}zu", len, readableSize);
        return memoryGraphics;
    }
    memoryGraphics.resize(count);
    for (uint64_t index = 0; index < count; index++) {
        sptr<MemoryGraphic> item = reply.ReadParcelable<MemoryGraphic>();
        if (item == nullptr) {
            continue;
        } else {
            memoryGraphics[index] = *item;
        }
    }
    return memoryGraphics;
}

bool RSRenderServiceConnectionProxy::GetTotalAppMemSize(float& cpuMemSize, float& gpuMemSize)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    MemoryGraphic memoryGraphic;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_TOTAL_APP_MEM_SIZE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }

    cpuMemSize = reply.ReadFloat();
    gpuMemSize = reply.ReadFloat();
    return true;
}

MemoryGraphic RSRenderServiceConnectionProxy::GetMemoryGraphic(int pid)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    MemoryGraphic memoryGraphic;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return memoryGraphic;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteInt32(pid)) {
        return memoryGraphic;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_MEMORY_GRAPHIC);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return memoryGraphic;
    }
    sptr<MemoryGraphic> pMemoryGraphic(reply.ReadParcelable<MemoryGraphic>());
    if (pMemoryGraphic == nullptr) {
        return memoryGraphic;
    }
    memoryGraphic = *pMemoryGraphic;
    return memoryGraphic;
}

RSScreenCapability RSRenderServiceConnectionProxy::GetScreenCapability(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    RSScreenCapability screenCapability;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return screenCapability;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return screenCapability;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_CAPABILITY);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return screenCapability;
    }

    sptr<RSScreenCapability> pScreenCapability(reply.ReadParcelable<RSScreenCapability>());
    if (pScreenCapability == nullptr) {
        return screenCapability;
    }
    screenCapability = *pScreenCapability;
    return screenCapability;
}

ScreenPowerStatus RSRenderServiceConnectionProxy::GetScreenPowerStatus(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return INVALID_POWER_STATUS;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return INVALID_POWER_STATUS;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_POWER_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return INVALID_POWER_STATUS;
    }
    return static_cast<ScreenPowerStatus>(reply.ReadUint32());
}

RSScreenData RSRenderServiceConnectionProxy::GetScreenData(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    RSScreenData screenData;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return screenData;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return screenData;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_DATA);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return screenData;
    }
    sptr<RSScreenData> pScreenData(reply.ReadParcelable<RSScreenData>());
    if (pScreenData == nullptr) {
        return screenData;
    }
    screenData = *pScreenData;
    return screenData;
}

int32_t RSRenderServiceConnectionProxy::GetScreenBacklight(ScreenId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return INVALID_BACKLIGHT_VALUE;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return INVALID_BACKLIGHT_VALUE;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_BACK_LIGHT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return INVALID_BACKLIGHT_VALUE;
    }
    int32_t level = reply.ReadInt32();
    return level;
}

void RSRenderServiceConnectionProxy::SetScreenBacklight(ScreenId id, uint32_t level)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteUint32(level)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_BACK_LIGHT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }
}

void RSRenderServiceConnectionProxy::RegisterBufferClearListener(
    NodeId id, sptr<RSIBufferClearCallback> callback)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterBufferClearListener: callback is nullptr.");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_CLEAR_LISTENER);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterBufferClearListener: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::RegisterBufferAvailableListener(
    NodeId id, sptr<RSIBufferAvailableCallback> callback, bool isFromRenderThread)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterBufferAvailableListener: callback is nullptr.");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return;
    }
    if (!data.WriteBool(isFromRenderThread)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_BUFFER_AVAILABLE_LISTENER);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterBufferAvailableListener: Send Request err.");
        return;
    }
}

int32_t RSRenderServiceConnectionProxy::GetScreenSupportedColorGamuts(ScreenId id, std::vector<ScreenColorGamut>& mode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_GAMUTS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        mode.clear();
        std::vector<uint32_t> modeRecv;
        reply.ReadUInt32Vector(&modeRecv);
        for (auto i : modeRecv) {
            mode.push_back(static_cast<ScreenColorGamut>(i));
        }
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenSupportedMetaDataKeys(
    ScreenId id, std::vector<ScreenHDRMetadataKey>& keys)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_METADATAKEYS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        keys.clear();
        std::vector<uint32_t> keyRecv;
        reply.ReadUInt32Vector(&keyRecv);
        for (auto i : keyRecv) {
            keys.push_back(static_cast<ScreenHDRMetadataKey>(i));
        }
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenColorGamut(ScreenId id, ScreenColorGamut& mode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_GAMUT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        mode = static_cast<ScreenColorGamut>(reply.ReadUint32());
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetScreenColorGamut(ScreenId id, int32_t modeIdx)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteInt32(modeIdx)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_GAMUT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetScreenGamutMap(ScreenId id, ScreenGamutMap mode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(mode)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_GAMUT_MAP);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetScreenCorrection(ScreenId id, ScreenRotation screenRotation)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(screenRotation))) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_CORRECTION);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenGamutMap(ScreenId id, ScreenGamutMap& mode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_GAMUT_MAP);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        mode = static_cast<ScreenGamutMap>(reply.ReadUint32());
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenHDRCapability(ScreenId id, RSScreenHDRCapability& screenHdrCapability)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_HDR_CAPABILITY);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result != SUCCESS) {
        return result;
    }
    sptr<RSScreenHDRCapability> pScreenCapability = reply.ReadParcelable<RSScreenHDRCapability>();
    if (pScreenCapability == nullptr) {
        return RS_CONNECTION_ERROR;
    }
    screenHdrCapability = *pScreenCapability;
    return SUCCESS;
}

int32_t RSRenderServiceConnectionProxy::GetPixelFormat(ScreenId id, GraphicPixelFormat& pixelFormat)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_PIXEL_FORMAT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        pixelFormat = static_cast<GraphicPixelFormat>(reply.ReadUint32());
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetPixelFormat(ScreenId id, GraphicPixelFormat pixelFormat)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(pixelFormat))) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_PIXEL_FORMAT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenSupportedHDRFormats(
    ScreenId id, std::vector<ScreenHDRFormat>& hdrFormats)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_HDR_FORMATS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        hdrFormats.clear();
        std::vector<uint32_t> hdrFormatsRecv;
        reply.ReadUInt32Vector(&hdrFormatsRecv);
        std::transform(hdrFormatsRecv.begin(), hdrFormatsRecv.end(), back_inserter(hdrFormats),
                       [](uint32_t i) -> ScreenHDRFormat {return static_cast<ScreenHDRFormat>(i);});
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenHDRFormat(ScreenId id, ScreenHDRFormat& hdrFormat)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_HDR_FORMAT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        hdrFormat = static_cast<ScreenHDRFormat>(reply.ReadUint32());
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetScreenHDRFormat(ScreenId id, int32_t modeIdx)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteInt32(modeIdx)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_HDR_FORMAT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenSupportedColorSpaces(
    ScreenId id, std::vector<GraphicCM_ColorSpaceType>& colorSpaces)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_SUPPORTED_COLORSPACES);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        colorSpaces.clear();
        std::vector<uint32_t> colorSpacesRecv;
        reply.ReadUInt32Vector(&colorSpacesRecv);
        std::transform(colorSpacesRecv.begin(), colorSpacesRecv.end(), back_inserter(colorSpaces),
                       [](uint32_t i) -> GraphicCM_ColorSpaceType {return static_cast<GraphicCM_ColorSpaceType>(i);});
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType& colorSpace)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_COLORSPACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        colorSpace = static_cast<GraphicCM_ColorSpaceType>(reply.ReadUint32());
    }
    return result;
}

int32_t RSRenderServiceConnectionProxy::SetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType colorSpace)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteInt32(colorSpace)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_COLORSPACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::GetScreenType(ScreenId id, RSScreenType& screenType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_SCREEN_TYPE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    if (result == SUCCESS) {
        screenType = static_cast<RSScreenType>(reply.ReadUint32());
    }
    return result;
}

bool RSRenderServiceConnectionProxy::GetBitmap(NodeId id, Drawing::Bitmap& bitmap)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_BITMAP);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    bool result = reply.ReadBool();
    if (!result || !RSMarshallingHelper::Unmarshalling(reply, bitmap)) {
        RS_LOGE("RSRenderServiceConnectionProxy::GetBitmap: Unmarshalling failed");
        return false;
    }
    return true;
}

bool RSRenderServiceConnectionProxy::SetVirtualMirrorScreenCanvasRotation(ScreenId id, bool canvasRotation)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return false;
    }
    if (!data.WriteBool(canvasRotation)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_MIRROR_SCREEN_CANVAS_ROTATION);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

bool RSRenderServiceConnectionProxy::SetVirtualMirrorScreenScaleMode(ScreenId id, ScreenScaleMode scaleMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return false;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(scaleMode))) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_MIRROR_SCREEN_SCALE_MODE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

bool RSRenderServiceConnectionProxy::GetPixelmap(NodeId id, std::shared_ptr<Media::PixelMap> pixelmap,
    const Drawing::Rect* rect, std::shared_ptr<Drawing::DrawCmdList> drawCmdList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return false;
    }
    if (!data.WriteParcelable(pixelmap.get())) {
        return false;
    }
    RSMarshallingHelper::Marshalling(data, *rect);
    RSMarshallingHelper::Marshalling(data, drawCmdList);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_PIXELMAP);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    bool result = reply.ReadBool();
    if (!result || !RSMarshallingHelper::Unmarshalling(reply, pixelmap)) {
        RS_LOGD("RSRenderServiceConnectionProxy::GetPixelmap: GetPixelmap failed");
        return false;
    }
    return true;
}

bool RSRenderServiceConnectionProxy::RegisterTypeface(uint64_t globalUniqueId,
    std::shared_ptr<Drawing::Typeface>& typeface)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t hash = typeface->GetHash();
    if (!data.WriteUint64(globalUniqueId)) {
        return false;
    }
    if (!data.WriteUint32(hash)) {
        return false;
    }

    if (hash) { // if adapter does not provide hash, use old path
        MessageParcel reply2;
        uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NEED_REGISTER_TYPEFACE);
        int32_t err = Remote()->SendRequest(code, data, reply2, option);
        if (err != NO_ERROR) {
            RS_LOGW("Check if RegisterTypeface is needed failed, err:%{public}d", err);
            return false;
        }
        if (!reply2.ReadBool()) {
            return true; // the hash exists on server, no need to resend full data
        }
    }

    RSMarshallingHelper::Marshalling(data, typeface);

    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_TYPEFACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        RS_LOGD("RSRenderServiceConnectionProxy::RegisterTypeface: RegisterTypeface failed");
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

bool RSRenderServiceConnectionProxy::UnRegisterTypeface(uint64_t globalUniqueId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint64(globalUniqueId)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::UNREGISTER_TYPEFACE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        RS_LOGD("RSRenderServiceConnectionProxy::UnRegisterTypeface: send request failed");
        return false;
    }

    return true;
}

int32_t RSRenderServiceConnectionProxy::SetScreenSkipFrameInterval(ScreenId id, uint32_t skipFrameInterval)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(skipFrameInterval)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_SCREEN_SKIP_FRAME_INTERVAL);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::RegisterOcclusionChangeCallback(sptr<RSIOcclusionChangeCallback> callback)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterOcclusionChangeCallback: callback is nullptr.");
        return INVALID_ARGUMENTS;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_OCCLUSION_CHANGE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    } else {
        return SUCCESS;
    }
}

int32_t RSRenderServiceConnectionProxy::RegisterSurfaceOcclusionChangeCallback(
    NodeId id, sptr<RSISurfaceOcclusionChangeCallback> callback, std::vector<float>& partitionPoints)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterSurfaceOcclusionChangeCallback: callback is nullptr.");
        return INVALID_ARGUMENTS;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteFloatVector(partitionPoints)) {
        return WRITE_PARCEL_ERR;
    }

    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::REGISTER_SURFACE_OCCLUSION_CHANGE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::UnRegisterSurfaceOcclusionChangeCallback(NodeId id)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }

    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::UNREGISTER_SURFACE_OCCLUSION_CHANGE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::RegisterHgmConfigChangeCallback(sptr<RSIHgmConfigChangeCallback> callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_HGM_CFG_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterHgmConfigChangeCallback: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::RegisterHgmRefreshRateModeChangeCallback(
    sptr<RSIHgmConfigChangeCallback> callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteRemoteObject(callback->AsObject())) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REFRESH_RATE_MODE_CHANGE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterHgmRefreshRateModeChangeCallback: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t RSRenderServiceConnectionProxy::RegisterHgmRefreshRateUpdateCallback(
    sptr<RSIHgmConfigChangeCallback> callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (callback) {
        data.WriteRemoteObject(callback->AsObject());
    } else {
        data.WriteRemoteObject(nullptr);
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REFRESH_RATE_UPDATE_CALLBACK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterHgmRefreshRateModeChangeCallback: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

void RSRenderServiceConnectionProxy::SetAppWindowNum(uint32_t num)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteUint32(num)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_APP_WINDOW_NUM);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetAppWindowNum: Send Request err.");
        return;
    }
}

bool RSRenderServiceConnectionProxy::SetSystemAnimatedScenes(SystemAnimatedScenes systemAnimatedScenes)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint32(static_cast<uint32_t>(systemAnimatedScenes))) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::SET_SYSTEM_ANIMATED_SCENES);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

bool RSRenderServiceConnectionProxy::SetWatermark(const std::string& name, std::shared_ptr<Media::PixelMap> watermark)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    data.WriteString(name);
    data.WriteParcelable(watermark.get());
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_WATERMARK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetWatermark: Send Request err.");
        return false;
    }
    return true;
}

void RSRenderServiceConnectionProxy::ShowWatermark(const std::shared_ptr<Media::PixelMap> &watermarkImg, bool isShow)
{
    if (watermarkImg == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ShowWatermark: watermarkImg is nullptr.");
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteParcelable(watermarkImg.get())) {
        return;
    }
    if (!data.WriteBool(isShow)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SHOW_WATERMARK);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ShowWatermark: Send Request err.");
        return;
    }
}

int32_t RSRenderServiceConnectionProxy::ResizeVirtualScreen(ScreenId id, uint32_t width, uint32_t height)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ResizeVirtualScreen: WriteInterfaceToken err.");
        return WRITE_PARCEL_ERR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(width)) {
        return WRITE_PARCEL_ERR;
    }
    if (!data.WriteUint32(height)) {
        return WRITE_PARCEL_ERR;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::RESIZE_VIRTUAL_SCREEN);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ResizeVirtualScreen: Send Request err.");
        return RS_CONNECTION_ERROR;
    }
    int32_t status = reply.ReadInt32();
    return status;
}

void RSRenderServiceConnectionProxy::ReportJankStats()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_JANK_STATS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ReportJankStats: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::ReportEventResponse(DataBaseRs info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    ReportDataBaseRs(data, reply, option, info);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_RESPONSE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ReportEventResponse: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::ReportEventComplete(DataBaseRs info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    ReportDataBaseRs(data, reply, option, info);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_COMPLETE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ReportEventComplete: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::ReportEventJankFrame(DataBaseRs info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    ReportDataBaseRs(data, reply, option, info);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_JANK_FRAME);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ReportEventJankFrame: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::ReportDataBaseRs(
    MessageParcel& data, MessageParcel& reply, MessageOption& option, DataBaseRs info)
{
    if (!data.WriteInt32(info.appPid)) {
        return;
    }
    if (!data.WriteInt32(info.eventType)) {
        return;
    }
    if (!data.WriteInt32(info.versionCode)) {
        return;
    }
    if (!data.WriteInt64(info.uniqueId)) {
        return;
    }
    if (!data.WriteInt64(info.inputTime)) {
        return;
    }
    if (!data.WriteInt64(info.beginVsyncTime) || !data.WriteInt64(info.endVsyncTime)) {
        return;
    }
    if (!data.WriteBool(info.isDisplayAnimator)) {
        return;
    }
    if (!data.WriteString(info.sceneId)) {
        return;
    }
    if (!data.WriteString(info.versionName)) {
        return;
    }
    if (!data.WriteString(info.bundleName)) {
        return;
    }
    if (!data.WriteString(info.processName)) {
        return;
    }
    if (!data.WriteString(info.abilityName)) {
        return;
    }
    if (!data.WriteString(info.pageUrl)) {
        return;
    }
    if (!data.WriteString(info.sourceType)) {
        return;
    }
    if (!data.WriteString(info.note)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
}

void RSRenderServiceConnectionProxy::ReportGameStateDataRs(
    MessageParcel& data, MessageParcel& reply, MessageOption& option, GameStateData info)
{
    if (!data.WriteInt32(info.pid)) {
        return;
    }
    if (!data.WriteInt32(info.uid)) {
        return;
    }
    if (!data.WriteInt32(info.state)) {
        return;
    }
    if (!data.WriteInt32(info.renderTid)) {
        return;
    }
    if (!data.WriteString(info.bundleName)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
}

void RSRenderServiceConnectionProxy::ReportGameStateData(GameStateData info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    ReportGameStateDataRs(data, reply, option, info);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REPORT_EVENT_GAMESTATE);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::ReportGameStateData: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::SetHardwareEnabled(NodeId id, bool isEnabled, SelfDrawingNodeType selfDrawingType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint64(id)) {
        return;
    }
    if (!data.WriteBool(isEnabled)) {
        return;
    }
    if (!data.WriteUint8(static_cast<uint8_t>(selfDrawingType))) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_HARDWARE_ENABLED);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetHardwareEnabled: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::NotifyLightFactorStatus(bool isSafe)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(isSafe)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_LIGHT_FACTOR_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::NotifyLightFactorStatus: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::NotifyPackageEvent(uint32_t listSize, const std::vector<std::string>& packageList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (listSize != packageList.size()) {
        ROSEN_LOGE("input size doesn't match");
        return;
    }
    if (!data.WriteUint32(listSize)) {
        return;
    }
    for (auto pkg : packageList) {
        if (!data.WriteString(pkg)) {
            return;
        }
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_PACKAGE_EVENT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::NotifyPackageEvent: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::NotifyRefreshRateEvent(const EventInfo& eventInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(eventInfo.eventName)) {
        return;
    }
    if (!data.WriteBool(eventInfo.eventStatus)) {
        return;
    }
    if (!data.WriteUint32(eventInfo.minRefreshRate)) {
        return;
    }
    if (!data.WriteUint32(eventInfo.maxRefreshRate)) {
        return;
    }
    if (!data.WriteString(eventInfo.description)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_REFRESH_RATE_EVENT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::NotifyRefreshRateEvent: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::NotifyTouchEvent(int32_t touchStatus, int32_t touchCnt)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(touchStatus)) {
        return;
    }
    if (!data.WriteInt32(touchCnt)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_TOUCH_EVENT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::NotifyTouchEvent: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::NotifyDynamicModeEvent(bool enableDynamicMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(enableDynamicMode)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::NOTIFY_DYNAMIC_MODE_EVENT);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::NotifyDynamicModeEvent: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::SetCacheEnabledForRotation(bool isEnabled)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(isEnabled)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_ROTATION_CACHE_ENABLED);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetCacheEnabledForRotation: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::SetDefaultDeviceRotationOffset(uint32_t offset)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(offset)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_DEFAULT_DEVICE_ROTATION_OFFSET);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetDefaultDeviceRotationOffset: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::SetOnRemoteDiedCallback(const OnRemoteDiedCallback& callback)
{
    OnRemoteDiedCallback_ = callback;
}

void RSRenderServiceConnectionProxy::RunOnRemoteDiedCallback()
{
    if (OnRemoteDiedCallback_) {
        OnRemoteDiedCallback_();
    }
}

std::vector<ActiveDirtyRegionInfo> RSRenderServiceConnectionProxy::GetActiveDirtyRegionInfo()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::vector<ActiveDirtyRegionInfo> activeDirtyRegionInfos;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return activeDirtyRegionInfos;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_ACTIVE_DIRTY_REGION_INFO);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::GetActiveDirtyRegionInfo: Send Request err.");
        return activeDirtyRegionInfos;
    }
    int32_t activeDirtyRegionInfosSize = reply.ReadInt32();
    while (activeDirtyRegionInfosSize--) {
        activeDirtyRegionInfos.emplace_back(ActiveDirtyRegionInfo(reply.ReadInt64(), reply.ReadInt32(),
            reply.ReadInt32(), reply.ReadString()));
    }
    return activeDirtyRegionInfos;
}

GlobalDirtyRegionInfo RSRenderServiceConnectionProxy::GetGlobalDirtyRegionInfo()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    GlobalDirtyRegionInfo globalDirtyRegionInfo;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return globalDirtyRegionInfo;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_GLOBAL_DIRTY_REGION_INFO);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::GetGlobalDirtyRegionInfo: Send Request err.");
        return globalDirtyRegionInfo;
    }
    return GlobalDirtyRegionInfo(reply.ReadInt64(), reply.ReadInt32(), reply.ReadInt32());
}

LayerComposeInfo RSRenderServiceConnectionProxy::GetLayerComposeInfo()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    LayerComposeInfo layerComposeInfo;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return layerComposeInfo;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::GET_LAYER_COMPOSE_INFO);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::GetLayerComposeInfo: Send Request err.");
        return layerComposeInfo;
    }
    return LayerComposeInfo(reply.ReadInt32(), reply.ReadInt32(), reply.ReadInt32());
}

HwcDisabledReasonInfos RSRenderServiceConnectionProxy::GetHwcDisabledReasonInfo()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    HwcDisabledReasonInfos hwcDisabledReasonInfos;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return hwcDisabledReasonInfos;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::
        GET_HARDWARE_COMPOSE_DISABLED_REASON_INFO);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::GetHwcDisabledReasonInfo: Send Request err.");
        return hwcDisabledReasonInfos;
    }
    int32_t size = reply.ReadInt32();
    size_t readableSize = reply.GetReadableBytes() / (sizeof(HwcDisabledReasonInfo) - HWC_DISABLED_REASON_INFO_OFFSET);
    size_t len = static_cast<size_t>(size);
    if (len > readableSize || len > hwcDisabledReasonInfos.max_size()) {
        RS_LOGE("RSRenderServiceConnectionProxy GetHwcDisabledReasonInfo Failed read vector, size:%{public}zu,"
            " readableSize:%{public}zu", len, readableSize);
        return hwcDisabledReasonInfos;
    }

    HwcDisabledReasonInfo hwcDisabledReasonInfo;
    while (size--) {
        for (int32_t pos = 0; pos < HwcDisabledReasons::DISABLED_REASON_LENGTH; pos++) {
            hwcDisabledReasonInfo.disabledReasonStatistics[pos] = reply.ReadInt32();
        }
        hwcDisabledReasonInfo.pidOfBelongsApp = reply.ReadInt32();
        hwcDisabledReasonInfo.nodeName = reply.ReadString();
        hwcDisabledReasonInfos.emplace_back(hwcDisabledReasonInfo);
    }
    return hwcDisabledReasonInfos;
}

void RSRenderServiceConnectionProxy::SetVmaCacheStatus(bool flag)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(flag)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VMA_CACHE_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVmaCacheStatus %d: Send Request err.", flag);
        return;
    }
}

#ifdef TP_FEATURE_ENABLE
void RSRenderServiceConnectionProxy::SetTpFeatureConfig(int32_t feature, const char* config)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }

    if (!data.WriteInt32(feature)) {
        return;
    }

    if (!data.WriteCString(config)) {
        return;
    }

    option.SetFlags(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_TP_FEATURE_CONFIG);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return;
    }
}
#endif
void RSRenderServiceConnectionProxy::SetVirtualScreenUsingStatus(bool isVirtualScreenUsingStatus)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(isVirtualScreenUsingStatus)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_USING_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetVirtualScreenUsingStatus: Send Request err.");
        return;
    }
}

void RSRenderServiceConnectionProxy::SetCurtainScreenUsingStatus(bool isCurtainScreenOn)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(isCurtainScreenOn)) {
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_CURTAIN_SCREEN_USING_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetCurtainScreenUsingStatus: Send Request err.");
        return;
    }
}

int32_t RSRenderServiceConnectionProxy::RegisterUIExtensionCallback(
    uint64_t userId, sptr<RSIUIExtensionCallback> callback)
{
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::RegisterUIExtensionCallback: callback is nullptr.");
        return INVALID_ARGUMENTS;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return RS_CONNECTION_ERROR;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (data.WriteUint64(userId) && data.WriteRemoteObject(callback->AsObject())) {
        uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::REGISTER_UIEXTENSION_CALLBACK);
        int32_t err = Remote()->SendRequest(code, data, reply, option);
        if (err != NO_ERROR) {
            return RS_CONNECTION_ERROR;
        }
        int32_t result = reply.ReadInt32();
        return result;
    } else {
        return RS_CONNECTION_ERROR;
    }
}

bool RSRenderServiceConnectionProxy::SetVirtualScreenStatus(ScreenId id, VirtualScreenStatus screenStatus)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (!data.WriteUint64(id)) {
        return false;
    }
    if (!data.WriteUint8(static_cast<uint8_t>(screenStatus))) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_VIRTUAL_SCREEN_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

bool RSRenderServiceConnectionProxy::SetAncoForceDoDirect(bool direct)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return false;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    if (data.WriteBool(direct)) {
        uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_ANCO_FORCE_DO_DIRECT);
        int32_t err = Remote()->SendRequest(code, data, reply, option);
        if (err != NO_ERROR) {
            return RS_CONNECTION_ERROR;
        }
        bool result = reply.ReadBool();
        return result;
    } else {
        return RS_CONNECTION_ERROR;
    }
}

void RSRenderServiceConnectionProxy::SetFreeMultiWindowStatus(bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetFreeMultiWindowStatus: write token err.");
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteBool(enable)) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetFreeMultiWindowStatus: write bool val err.");
        return;
    }
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_FREE_MULTI_WINDOW_STATUS);
    int32_t err = Remote()->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSRenderServiceConnectionProxy::SetFreeMultiWindowStatus: Send Request err.");
    }
}

} // namespace Rosen
} // namespace OHOS
