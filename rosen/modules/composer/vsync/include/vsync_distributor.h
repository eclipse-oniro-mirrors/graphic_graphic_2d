/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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


#ifndef VSYNC_VSYNC_DISTRIBUTOR_H
#define VSYNC_VSYNC_DISTRIBUTOR_H

#include <refbase.h>

#include <mutex>
#include <vector>
#include <thread>
#include <condition_variable>

#include "local_socketpair.h"
#include "vsync_controller.h"
#include "vsync_connection_stub.h"

#include "vsync_system_ability_listener.h"

#if defined(RS_ENABLE_DVSYNC)
#include "dvsync.h"
#endif

namespace OHOS {
namespace Rosen {
class VSyncDistributor;
struct ConnectionInfo {
    std::string name_;
    uint64_t postVSyncCount_;
    ConnectionInfo(std::string name): postVSyncCount_(0)
    {
        this->name_ = name;
    }
};
typedef void (*GCNotifyTask)(bool);

class VSyncConnection : public VSyncConnectionStub {
public:
    // id for LTPO, windowNodeId for vsync rate control
    VSyncConnection(const sptr<VSyncDistributor>& distributor, std::string name,
                    const sptr<IRemoteObject>& token = nullptr, uint64_t id = 0, uint64_t windowNodeId = 0);
    ~VSyncConnection();

    virtual VsyncError RequestNextVSync() override;
    virtual VsyncError RequestNextVSync(const std::string &fromWhom, int64_t lastVSyncTS) override;
    virtual VsyncError GetReceiveFd(int32_t &fd) override;
    virtual VsyncError SetVSyncRate(int32_t rate) override;
    virtual VsyncError Destroy() override;
    virtual VsyncError SetUiDvsyncSwitch(bool vsyncSwitch) override;
    virtual VsyncError SetUiDvsyncConfig(int32_t bufferCount) override;
    virtual VsyncError SetNativeDVSyncSwitch(bool dvsyncSwitch) override;
    int32_t PostEvent(int64_t now, int64_t period, int64_t vsyncCount);
    inline void SetGCNotifyTask(GCNotifyTask hook)
    {
        gcNotifyTask_ = hook;
    }
    void RegisterDeathRecipient();

    int32_t rate_; // used for LTPS
    int32_t highPriorityRate_ = -1;
    bool highPriorityState_ = false;
    ConnectionInfo info_;
    bool triggerThisTime_ = false; // used for LTPO
    uint64_t id_ = 0;
    uint64_t windowNodeId_ = 0;
    uint32_t vsyncPulseFreq_ = 1;
    int64_t referencePulseCount_ = 0;
    uint32_t refreshRate_ = 0;
    int32_t proxyPid_;
    bool rnvTrigger_ = false;
private:
    VsyncError CleanAllLocked();
    class VSyncConnectionDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit VSyncConnectionDeathRecipient(wptr<VSyncConnection> conn);
        virtual ~VSyncConnectionDeathRecipient() = default;

        void OnRemoteDied(const wptr<IRemoteObject>& token) override;

    private:
        wptr<VSyncConnection> conn_;
    };
    GCNotifyTask gcNotifyTask_ = nullptr;
    sptr<VSyncConnectionDeathRecipient> vsyncConnDeathRecipient_ = nullptr;
    sptr<IRemoteObject> token_ = nullptr;
    // Circular reference， need check
    wptr<VSyncDistributor> distributor_;
    sptr<LocalSocketPair> socketPair_;
    bool isDead_;
    std::mutex mutex_;
    std::mutex postEventMutex_;
    bool isFirstRequestVsync_ = true;
    bool isFirstSendVsync_ = true;
};

class VSyncDistributor : public RefBase, public VSyncController::Callback {
public:

    VSyncDistributor(sptr<VSyncController> controller, std::string name);
    ~VSyncDistributor();
    // nocopyable
    VSyncDistributor(const VSyncDistributor &) = delete;
    VSyncDistributor &operator=(const VSyncDistributor &) = delete;

    VsyncError AddConnection(const sptr<VSyncConnection>& connection, uint64_t windowNodeId = 0);
    VsyncError RemoveConnection(const sptr<VSyncConnection> &connection);

    // fromWhom indicates whether the source is animate or non-animate
    // lastVSyncTS indicates last vsync time, 0 when non-animate
    VsyncError RequestNextVSync(const sptr<VSyncConnection> &connection, const std::string &fromWhom = "unknown",
                                int64_t lastVSyncTS = 0);
    VsyncError SetVSyncRate(int32_t rate, const sptr<VSyncConnection>& connection);
    VsyncError SetHighPriorityVSyncRate(int32_t highPriorityRate, const sptr<VSyncConnection>& connection);
    VsyncError SetQosVSyncRate(uint64_t windowNodeId, int32_t rate, bool isSystemAnimateScene = false);
    VsyncError SetQosVSyncRateByPidPublic(uint32_t pid, uint32_t rate, bool isSystemAnimateScene);

    // used by DVSync
    bool IsDVsyncOn();
    void SetFrameIsRender(bool isRender);
    void MarkRSAnimate();
    void UnmarkRSAnimate();
    bool HasPendingUIRNV();
    uint32_t GetRefreshRate();
    void RecordVsyncModeChange(uint32_t refreshRate, int64_t period);
    bool IsUiDvsyncOn();
    VsyncError SetUiDvsyncSwitch(bool dvsyncSwitch, const sptr<VSyncConnection>& connection);
    VsyncError SetUiDvsyncConfig(int32_t bufferCount);
    int64_t GetUiCommandDelayTime();
    void UpdatePendingReferenceTime(int64_t &timeStamp);
    void SetHardwareTaskNum(uint32_t num);
    int64_t GetVsyncCount();
    uint64_t GetRealTimeOffsetOfDvsync(int64_t time);
    VsyncError SetNativeDVSyncSwitch(bool dvsyncSwitch, const sptr<VSyncConnection> &connection);
    void SetHasNativeBuffer();
    void PrintConnectionsStatus();
    void FirstRequestVsync();
    void NotifyPackageEvent(const std::vector<std::string>& packageList);
    void NotifyTouchEvent(int32_t touchStatus, int32_t touchCnt);
    bool AdaptiveDVSyncEnable(std::string nodeName);

    // used by V Rate
    std::vector<uint64_t> GetSurfaceNodeLinkerIds(uint64_t windowNodeId);

private:

    // check, add more info
    struct VSyncEvent {
        int64_t timestamp;
        int64_t vsyncCount; // used for LTPS
        int64_t period;
        int64_t vsyncPulseCount; // used for LTPO
        uint32_t refreshRate;
    };
    void ThreadMain();
    void EnableVSync();
    void DisableVSync();
    void OnVSyncEvent(int64_t now, int64_t period,
        uint32_t refreshRate, VSyncMode vsyncMode, uint32_t vsyncMaxRefreshRate);
    void CollectConnections(bool &waitForVSync, int64_t timestamp,
                            std::vector<sptr<VSyncConnection>> &conns, int64_t vsyncCount, bool isDvsyncThread = false);
    VsyncError QosGetPidByName(const std::string& name, uint32_t& pid);
    constexpr pid_t ExtractPid(uint64_t id);
    void PostVSyncEvent(const std::vector<sptr<VSyncConnection>> &conns, int64_t timestamp, bool isDvsyncThread);
    void ChangeConnsRateLocked(uint32_t vsyncMaxRefreshRate);
    void CollectConnectionsLTPO(bool &waitForVSync, int64_t timestamp,
        std::vector<sptr<VSyncConnection>> &conns, int64_t vsyncCount, bool isDvsyncThread = false);
    /* std::pair<id, refresh rate> */
    void OnConnsRefreshRateChanged(const std::vector<std::pair<uint64_t, uint32_t>> &refreshRates);
    VsyncError SetQosVSyncRateByPid(uint32_t pid, int32_t rate, bool isSystemAnimateScene = false);

#ifdef COMPOSER_SCHED_ENABLE
    void SubScribeSystemAbility(const std::string& threadName);
#endif
    void WaitForVsyncOrRequest(std::unique_lock<std::mutex> &locker);
    void WaitForVsyncOrTimeOut(std::unique_lock<std::mutex> &locker);
    void CollectConns(bool &waitForVSync, int64_t &timestamp,
        std::vector<sptr<VSyncConnection>> &conns, bool isDvsyncThread);
    bool PostVSyncEventPreProcess(int64_t &timestamp, std::vector<sptr<VSyncConnection>> &conns);
    void CheckNeedDisableDvsync(int64_t now, int64_t period);
    void OnVSyncTrigger(int64_t now, int64_t period,
        uint32_t refreshRate, VSyncMode vsyncMode, uint32_t vsyncMaxRefreshRate);

    sptr<VSyncSystemAbilityListener> saStatusChangeListener_ = nullptr;
    std::thread threadLoop_;
    sptr<VSyncController> controller_;
    std::mutex mutex_;
    std::condition_variable con_;
    std::vector<sptr<VSyncConnection> > connections_;
    std::map<uint64_t, std::vector<sptr<VSyncConnection>>> connectionsMap_;
    std::map<uint64_t, std::vector<uint64_t>> pidWindowIdMap_;
    VSyncEvent event_;
    bool vsyncEnabled_;
    std::string name_;
    bool vsyncThreadRunning_ = false;
    std::vector<std::pair<uint64_t, uint32_t>> changingConnsRefreshRates_; // std::pair<id, refresh rate>
    VSyncMode vsyncMode_ = VSYNC_MODE_LTPS; // default LTPS
    std::mutex changingConnsRefreshRatesMtx_;
    uint32_t generatorRefreshRate_ = 0;
    std::unordered_map<int32_t, int32_t> connectionCounter_;
    uint32_t countTraceValue_ = 0;
#if defined(RS_ENABLE_DVSYNC)
    int32_t GetUIDVsyncPid();
    void SendConnectionsToVSyncWindow(int64_t now, int64_t period, uint32_t refreshRate, VSyncMode vsyncMode,
        std::unique_lock<std::mutex> &locker);
    void OnDVSyncTrigger(int64_t now, int64_t period,
        uint32_t refreshRate, VSyncMode vsyncMode, uint32_t vsyncMaxRefreshRate);
    sptr<DVsync> dvsync_ = nullptr;
    bool pendingRNVInVsync_ = false;  // for vsync switch to dvsync
    std::atomic<int64_t> lastDVsyncTS_ = 0;  // for dvsync switch to vsync
#endif
    bool isRs_ = false;
    std::atomic<bool> hasVsync_ = false;
    void ConnectionsPostEvent(std::vector<sptr<VSyncConnection>> &conns, int64_t now, int64_t period,
        uint32_t generatorRefreshRate, int64_t vsyncCount, bool isDvsyncController);
    void ConnPostEvent(sptr<VSyncConnection> con, int64_t now, int64_t period, int64_t vsyncCount);
    void TriggerNext(sptr<VSyncConnection> con);
    // Start of DVSync
    void DisableDVSyncController();
    void OnDVSyncEvent(int64_t now, int64_t period,
        uint32_t refreshRate, VSyncMode vsyncMode, uint32_t vsyncMaxRefreshRate);
    void InitDVSync();
    void DVSyncAddConnection(const sptr<VSyncConnection> &connection);
    void DVSyncDisableVSync();
    void RecordEnableVsync();
    void DVSyncRecordVSync(int64_t now, int64_t period, uint32_t refreshRate, bool isDvsyncController);
    bool DVSyncCheckSkipAndUpdateTs(const sptr<VSyncConnection> &connection, int64_t &timeStamp);
    bool DVSyncNeedSkipUi(const sptr<VSyncConnection> &connection);
    void DVSyncRecordRNV(const sptr<VSyncConnection> &connection, const std::string &fromWhom, int64_t lastVSyncTS);
    bool DVSyncCheckPreexecuteAndUpdateTs(const sptr<VSyncConnection> &connection, int64_t &timestamp,
        int64_t &period, int64_t &vsyncCount);
    sptr<VSyncController> dvsyncController_ = nullptr;
    bool dvsyncControllerEnabled_ = false;
    // End of DVSync
    int64_t beforeWaitRnvTime_ = 0;
    int64_t afterWaitRnvTime_ = 0;
    int64_t lastNotifyTime_ = 0;
    std::atomic<int64_t> beforePostEvent_ = 0;
    std::atomic<int64_t> startPostEvent_ = 0;
    bool isFirstRequest_ = false;
    bool isFirstSend_ = false;
};
} // namespace Rosen
} // namespace OHOS

#endif
