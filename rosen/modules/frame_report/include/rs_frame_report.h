/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef ROSEN_MODULE_RS_FRAME_REPORT_H
#define ROSEN_MODULE_RS_FRAME_REPORT_H

#include <string>
#include <unordered_map>

namespace OHOS {
namespace Rosen {

enum class FrameSchedEvent {
    SCHED_EVENT_BASE = 0,
    INIT = 1,
    RS_RENDER_START = 10001,
    RS_RENDER_END = 10002,
    RS_UNI_RENDER_START = 10003,
    RS_UNI_RENDER_END = 10004,
    RS_HARDWARE_START = 10005,
    RS_HARDWARE_END = 10006,
    RS_HARDWARE_INFO = 10007,
    RS_BUFFER_COUNT = 10008,
    RS_FRAME_DEADLINE = 10009,
    RS_UNBLOCK_MAINTHREAD = 10010,
    RS_POST_AND_WAIT = 10011,
    RS_BEGIN_FLUSH = 10012,
    RS_BLUR_PREDICT = 10013,
};

using FrameGetEnableFunc = int (*)();
using ReportSchedEventFunc = void (*)(FrameSchedEvent, const std::unordered_map<std::string, std::string>&);
using InitFunc = void (*)();
using ProcessCommandsStartFunc = void(*)();
using AnimateStartFunc = void(*)();
using RenderStartFunc = void(*)(uint64_t);
using ParallelRenderStartFunc = void(*)();
using RenderEndFunc = void(*)();
using ParallelRenderEndFunc = void(*)();
using SendCommandsStartFunc = void(*)();
using SetFrameParamFunc = void(*)(int, int, int, int);
class RsFrameReport final {
public:
    static RsFrameReport& GetInstance();
    void Init();
    int GetEnable();
    void ReportSchedEvent(FrameSchedEvent event, const std::unordered_map<std::string, std::string> &payload);

    void ProcessCommandsStart();
    void AnimateStart();
    void RenderStart(uint64_t timestamp);
    void RSRenderStart();
    void RenderEnd();
    void RSRenderEnd();
    void SendCommandsStart();
    void SetFrameParam(int requestId, int load, int schedFrameNum, int value);
    void UnblockMainThread();
    void PostAndWait();
    void BeginFlush();

private:
    RsFrameReport();
    ~RsFrameReport();
    bool LoadLibrary();
    void CloseLibrary();
    void *LoadSymbol(const char *symName);

    void *frameSchedHandle_ = nullptr;
    bool frameSchedSoLoaded_ = false;

    FrameGetEnableFunc frameGetEnableFunc_ = nullptr;
    ReportSchedEventFunc reportSchedEventFunc_ = nullptr;
    InitFunc initFunc_ = nullptr;
    ProcessCommandsStartFunc processCommandsStartFun_ = nullptr;
    AnimateStartFunc animateStartFunc_ = nullptr;
    RenderStartFunc renderStartFunc_ = nullptr;
    ParallelRenderStartFunc parallelRenderStartFunc_ = nullptr;
    RenderEndFunc renderEndFunc_ = nullptr;
    ParallelRenderEndFunc parallelRenderEndFunc_ = nullptr;
    SendCommandsStartFunc sendCommandsStartFunc_ = nullptr;
    SetFrameParamFunc setFrameParamFunc_ = nullptr;
};
} // namespace Rosen
} // namespace OHOS
#endif // ROSEN_MODULE_RS_FRAME_REPORT_H
