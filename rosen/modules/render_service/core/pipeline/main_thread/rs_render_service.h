/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_PIPELINE_RS_RENDER_SERVICE_H
#define RENDER_SERVICE_PIPELINE_RS_RENDER_SERVICE_H
#include <map>
#include <unordered_set>

#include "screen_manager/rs_screen_manager.h"
#include "transaction/rs_render_service_stub.h"
#include "vsync_controller.h"
#include "vsync_distributor.h"

namespace OHOS {
namespace Rosen {
class RSMainThread;
class RSRenderServiceConnection;

struct LoadOptParams {
    LoadOptParamsForScreen loadOptParamsForScreen;
};

class RSRenderService : public RSRenderServiceStub {
public:
    RSRenderService();
    ~RSRenderService() noexcept;

    RSRenderService(const RSRenderService&) = delete;
    RSRenderService& operator=(const RSRenderService&) = delete;

    bool Init();
    void Run();

private:
    int Dump(int fd, const std::vector<std::u16string>& args) override;
    void DoDump(std::unordered_set<std::u16string>& argSets, std::string& dumpString) const;
    void DumpNodesNotOnTheTree(std::string& dumpString) const;
    void DumpAllNodesMemSize(std::string& dumpString) const;
    void DumpGpuInfo(std::string& dumpString) const;
    void DumpRSEvenParam(std::string& dumpString) const;
    void DumpRenderServiceTree(std::string& dumpString, bool forceDumpSingleFrame = true) const;
    void DumpRefreshRateCounts(std::string& dumpString) const;
    void DumpClearRefreshRateCounts(std::string& dumpString) const;
    void DumpJankStatsRs(std::string& dumpString) const;
#ifdef RS_ENABLE_VK
    void DumpVkTextureLimit(std::string& dumpString) const;
#endif
    void DumpSurfaceNode(std::string& dumpString, NodeId id) const;

    void DumpExistPidMem(std::unordered_set<std::u16string>& argSets, std::string& dumpString) const;

    void WindowHitchsDump(std::unordered_set<std::u16string>& argSets, std::string& dumpString,
        const std::u16string& arg) const;
    void DumpMem(std::unordered_set<std::u16string>& argSets, std::string& dumpString) const;
    void DumpNode(std::unordered_set<std::u16string>& argSets, std::string& dumpString) const;
    void FPSDumpProcess(std::unordered_set<std::u16string>& argSets, std::string& dumpString,
        const std::u16string& arg) const;
    void DumpFps(std::string& dumpString, std::string& layerName) const;
    void FPSDumpClearProcess(std::unordered_set<std::u16string>& argSets,
        std::string& dumpString, const std::u16string& arg) const;
    void ClearFps(std::string& dumpString, std::string& layerName) const;

    sptr<RSIRenderServiceConnection> CreateConnection(const sptr<RSIConnectionToken>& token) override;
    void RemoveConnection(sptr<IRemoteObject> token);

    // RS dump init
    void RSGfxDumpInit();
    void RegisterRSGfxFuncs();
    void RegisterRSTreeFuncs();
    void RegisterMemFuncs();
    void RegisterFpsFuncs();
    void RegisterGpuFuncs();
    void RegisterBufferFuncs();
    void InitDVSyncParams(DVSyncFeatureParam &dvsyncParam);
    void InitLoadOptParams(LoadOptParams& loadOptParams);

    // RS Filter CCM init
    void FilterCCMInit();

    RSMainThread* mainThread_ = nullptr;
    sptr<RSScreenManager> screenManager_;

    friend class RSRenderServiceConnection;
    mutable std::mutex mutex_;
    std::map<sptr<IRemoteObject>, sptr<RSIRenderServiceConnection>> connections_;

    sptr<VSyncController> rsVSyncController_;
    sptr<VSyncController> appVSyncController_;

    sptr<VSyncDistributor> rsVSyncDistributor_;
    sptr<VSyncDistributor> appVSyncDistributor_;

#ifdef RS_PROFILER_ENABLED
    friend class RSProfiler;
#endif
};
} // Rosen
} // OHOS

#endif // RENDER_SERVICE_PIPELINE_RS_RENDER_SERVICE_H
