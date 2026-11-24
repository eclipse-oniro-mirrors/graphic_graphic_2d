/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <atomic>
#include <chrono>
#include <event_handler.h>
#include <iostream>

#include "animation/rs_animation_timing_curve.h"
#include "animation/rs_animation_timing_protocol.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_root_node.h"
#include "ui/rs_surface_node.h"
#include "ui/rs_ui_context.h"
#include "ui/rs_ui_director.h"

using namespace OHOS;
using namespace OHOS::Rosen;
using namespace std;

constexpr uint32_t ANIMATION_DURATION_MS = 500;
constexpr uint32_t PUMP_TICK_MS = 16;
constexpr uint32_t PUMP_MARGIN_MS = 300;
// stress mode: how many times the 4-case verification flow is repeated; one round takes ~9s
// (4 x sleep(2) + animation/pump windows), so the default 100 rounds take ~15 minutes
constexpr uint32_t STRESS_ROUNDS = 400 * 4;
constexpr int32_t STRESS_MODE = 2; // stdin selector value that enters the stress loop
constexpr int32_t SCREEN_WIDTH = 1260;
constexpr int32_t SCREEN_HEIGHT = 2720;

shared_ptr<RSNode> rootNode;
shared_ptr<RSCanvasNode> canvasNode;
shared_ptr<RSSurfaceNode> surfaceNode;

// case 1-4 counters, received fires on the IPC receiving thread,
// processed fires on the UI task runner thread
atomic<uint32_t> g_receivedCount(0);
atomic<uint32_t> g_processedCount(0);

void OnMessageReceived(uint32_t msgId)
{
    g_receivedCount++;
    cout << "[UIContextMessageCallback] received, msgId:" << msgId << ", total:" << g_receivedCount.load() << endl;
}

void OnMessageProcessed(uint32_t msgId)
{
    g_processedCount++;
    cout << "[UIContextMessageCallback] processed, msgId:" << msgId << ", total:" << g_processedCount.load() << endl;
}

// The animation is created by RSNode::Animate with the rsUIContext (single translate property as
// graphic_test does, one animation -> one FINISHED callback), so the animation command carries the
// context token and runs in the render service process. When it finishes, RS sends the
// RSAnimationCallback command (with the same token) back to this process, it enters uiContextCmdMap
// in RSUIDirector::ProcessMessages and passively triggers the registered callbacks.
// NOTE: the finish callback alone does NOT prove the RS round-trip. RSImplicitAnimator also runs it
// from two local fallbacks when no RSAnimationCallback ever arrives: ~duration ms after close when
// no implicit animation was created (ProcessEmptyAnimations), or ~max(2 x duration, 1000) ms as a
// safety net when the real FINISHED event was lost. Only a finish print accompanied by the
// received/processed prints above came from the real RS->client message path, so the elapsed time is
// printed to tell them apart on device.
void StartAnimatedProperty(const shared_ptr<RSUIContext>& rsUIContext, const char* tag, float tx, float ty)
{
    RSAnimationTimingProtocol protocol;
    protocol.SetDuration(ANIMATION_DURATION_MS);
    auto curve = RSAnimationTimingCurve::CreateCubicCurve(0.2f, 0.0f, 0.2f, 1.0f);
    auto propertyCallback = [tx, ty]() { canvasNode->SetTranslate(tx, ty, 0.f); };
    auto startTime = chrono::steady_clock::now();
    auto finishCallback = [tag, startTime]() {
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - startTime);
        cout << "[RSNode::Animate] " << tag << " finish callback after " << elapsed.count() << "ms" << endl;
    };
    RSNode::Animate(rsUIContext, protocol, curve, propertyCallback, finishCallback);
}

// One frame-pump tick: enqueues a visually neutral command (an alpha toggle on canvasNode, a
// different property from the animated translate) and flushes it, then re-posts itself on the UI
// task runner until the animation window ends. Every non-empty transaction wakes RS
// (RecvRSTransactionData -> RequestNextVSync), which re-runs RSMainThread::Animate and drives the
// animation to completion, so the real FINISHED comes back through the message path instead of
// the 1000ms client safety net. Ticks run on the runner — the same thread that dispatches the
// pushed RS callbacks — so pump ticks and callback processing stay serialized, matching
// production UI threading; a bare SendMessages with an empty payload sends no IPC at all
// (RSTransactionHandler::FlushImplicitTransaction skips empty transactions).
void PumpTick(const shared_ptr<AppExecFwk::EventHandler>& handler, const shared_ptr<RSUIDirector>& rsUiDirector,
    const shared_ptr<const chrono::steady_clock::time_point>& start, bool toggle)
{
    constexpr uint32_t windowMs = ANIMATION_DURATION_MS + PUMP_MARGIN_MS;
    auto elapsedMs = static_cast<uint32_t>(
        chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - *start).count());
    if (elapsedMs >= windowMs) {
        return;
    }
    auto nowNs = static_cast<uint64_t>(
        chrono::duration_cast<chrono::nanoseconds>(chrono::steady_clock::now().time_since_epoch()).count());
    rsUiDirector->SetTimeStamp(nowNs, "UiContextMsgCallbackDemo");
    canvasNode->SetAlpha(toggle ? 1.0f : 0.9999f);
    rsUiDirector->SendMessages();
    handler->PostTask(
        [handler, rsUiDirector, start, nextToggle = !toggle]() { PumpTick(handler, rsUiDirector, start, nextToggle); },
        PUMP_TICK_MS);
}

// Start the frame pump on the UI task runner for the animation window; the windowless headless
// surface has no other frame source while the RS-side animation is running.
void StartFramePump(const shared_ptr<AppExecFwk::EventHandler>& handler, const shared_ptr<RSUIDirector>& rsUiDirector)
{
    auto start = make_shared<const chrono::steady_clock::time_point>(chrono::steady_clock::now());
    handler->PostTask([handler, rsUiDirector, start]() { PumpTick(handler, rsUiDirector, start, false); });
}

// Verify mode: the 4-case flow (warm-up / register / unregister / nullptr). Returns whether all
// four cases passed, so the stress mode can aggregate over repetitions of this exact flow.
bool RunVerifyCases(const shared_ptr<AppExecFwk::EventHandler>& handler, const shared_ptr<RSUIDirector>& rsUiDirector,
    const shared_ptr<RSUIContext>& rsUIContext)
{
    // warm-up case, functionally identical to the unregister case: its return messages lag one case
    // boundary on this windowless surface, so they arrive during the NEXT case's window — while the
    // real callbacks are registered there. This case absorbs the lag and its own animation drives
    // the RS return path hot before the register case starts.
    cout << "\n===== case 1: warm-up (same as unregister case), callbacks should NOT be triggered =====" << endl;
    RSInterfaces::GetInstance().UnRegisterUIContextMessageCallbacks();
    uint32_t recvBefore = g_receivedCount;
    uint32_t procBefore = g_processedCount;
    StartAnimatedProperty(rsUIContext, "case1", 150.f, 150.f);
    StartFramePump(handler, rsUiDirector);
    sleep(2);
    bool case1Pass = (g_receivedCount == recvBefore && g_processedCount == procBefore);
    cout << "case1 " << (case1Pass ? "PASS" : "FAIL") << ", receivedCount:" << g_receivedCount << "/" << recvBefore
         << ", processedCount:" << g_processedCount << "/" << procBefore << endl;

    cout << "\n===== case 2: register callbacks, passively triggered by RS animation callback =====" << endl;
    RSInterfaces::GetInstance().RegisterUIContextMessageCallbacks(OnMessageReceived, OnMessageProcessed);
    StartAnimatedProperty(rsUIContext, "case2", 200.f, 200.f);
    StartFramePump(handler, rsUiDirector);
    sleep(2); // keep the total observation window at ~3s for late callbacks
    bool case2Pass = (g_receivedCount > 0 && g_processedCount > 0);
    cout << "case2 " << (case2Pass ? "PASS" : "FAIL") << ", receivedCount:" << g_receivedCount
         << ", processedCount:" << g_processedCount << endl;

    cout << "\n===== case 3: unregister, callbacks should NOT be triggered =====" << endl;
    RSInterfaces::GetInstance().UnRegisterUIContextMessageCallbacks();
    recvBefore = g_receivedCount;
    procBefore = g_processedCount;
    StartAnimatedProperty(rsUIContext, "case3", 400.f, 100.f);
    StartFramePump(handler, rsUiDirector);
    sleep(2);
    bool case3Pass = (g_receivedCount == recvBefore && g_processedCount == procBefore);
    cout << "case3 " << (case3Pass ? "PASS" : "FAIL") << ", receivedCount:" << g_receivedCount << "/" << recvBefore
         << ", processedCount:" << g_processedCount << "/" << procBefore << endl;

    cout << "\n===== case 4: register nullptr callbacks, should NOT be triggered and no crash =====" << endl;
    RSInterfaces::GetInstance().RegisterUIContextMessageCallbacks(nullptr, nullptr);
    recvBefore = g_receivedCount;
    procBefore = g_processedCount;
    StartAnimatedProperty(rsUIContext, "case4", 100.f, 400.f);
    StartFramePump(handler, rsUiDirector);
    sleep(2);
    bool case4Pass = (g_receivedCount == recvBefore && g_processedCount == procBefore);
    cout << "case4 " << (case4Pass ? "PASS" : "FAIL") << ", receivedCount:" << g_receivedCount << "/" << recvBefore
         << ", processedCount:" << g_processedCount << "/" << procBefore << endl;

    return case1Pass && case2Pass && case3Pass && case4Pass;
}

// Stress mode: the EXACT same 4-case flow as verify mode, repeated STRESS_ROUNDS times — no
// separate stress logic. Counters are reset before each round so every round is judged in
// isolation, like a fresh run; the reset is race-free because a round starts with callbacks
// unregistered (warm-up case), so stragglers from the previous round arrive silently and never
// touch the counters.
void RunStressTest(const shared_ptr<AppExecFwk::EventHandler>& handler, const shared_ptr<RSUIDirector>& rsUiDirector,
    const shared_ptr<RSUIContext>& rsUIContext)
{
    cout << "\n===== stress test: 4-case flow x " << STRESS_ROUNDS << " rounds =====" << endl;
    uint32_t allPassRounds = 0;
    for (uint32_t round = 1; round <= STRESS_ROUNDS; round++) {
        cout << "\n===== stress round " << round << "/" << STRESS_ROUNDS << " =====" << endl;
        g_receivedCount = 0;
        g_processedCount = 0;
        allPassRounds += RunVerifyCases(handler, rsUiDirector, rsUIContext) ? 1 : 0;
    }
    cout << "\n[stress] done, rounds:" << STRESS_ROUNDS << ", all-pass rounds:" << allPassRounds << endl;
    cout << "[stress] " << ((allPassRounds == STRESS_ROUNDS) ? "PASS" : "FAIL")
         << " (survived all rounds, per-round verdicts above)" << endl;
}

// No window_manager: create the surfaceNode with the rsUIContext and attach it to the default
// display node by AttachToDisplay; nodes are all created with the same rsUIContext (multi-instance)
void Init(const shared_ptr<RSUIDirector>& rsUiDirector, const shared_ptr<RSUIContext>& rsUIContext)
{
    RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "UiContextMsgCallbackDemo";
    surfaceNode =
        RSSurfaceNode::Create(surfaceNodeConfig, RSSurfaceNodeType::APP_WINDOW_NODE, true, false, rsUIContext);
    surfaceNode->SetBounds(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
    // raise the windowless surface above the launcher (as render_service_client_multi_instance_demo
    // does with POINTER_WINDOW_POSITION_Z), otherwise the layer is composed underneath and nothing
    // shows up; no SetFrameGravity here to avoid the display_manager include/dependency
    surfaceNode->SetPositionZ(RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode->SetBackgroundColor(Drawing::Color::COLOR_BLACK);
    rsUiDirector->SetRSSurfaceNode(surfaceNode);

    rootNode = RSRootNode::Create(false, false, rsUIContext);
    rootNode->SetBounds(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
    rootNode->SetFrame(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
    rootNode->SetBackgroundColor(Drawing::Color::COLOR_WHITE);
    rsUiDirector->SetRSRootNode(rootNode->ReinterpretCastTo<RSRootNode>());

    // animation target node must be created with the rsUIContext to carry the token
    canvasNode = RSCanvasNode::Create(false, false, rsUIContext);
    canvasNode->SetBounds(100, 100, 500, 500);
    canvasNode->SetFrame(100, 100, 500, 500);
    canvasNode->SetBackgroundColor(Drawing::Color::COLOR_RED);
    rootNode->AddChild(canvasNode, -1);
}

int main()
{
    cout << "rs client ui context message callback demo start!" << endl;

    // get the render service connection of the default screen and pass it to RSUIDirector::Create
    // (same as render_service_client_display_capture_format_demo), then the RSUIDirector and its
    // RSUIContext are bound to that connection
    auto& rsInterfaces = RSInterfaces::GetInstance();
    ScreenId defaultScreenId = rsInterfaces.GetDefaultScreenId();
    if (defaultScreenId == INVALID_SCREEN_ID) {
        cout << "get default screen id failed, demo exit" << endl;
        return 0;
    }
    sptr<IRemoteObject> connectToRender = rsInterfaces.GetConnectToRenderToken(defaultScreenId);
    auto rsUiDirector = RSUIDirector::Create(connectToRender);
    auto rsUIContext = rsUiDirector->GetRSUIContext();
    uint64_t token = (rsUIContext != nullptr) ? rsUIContext->GetToken() : 0;
    cout << "rsUIContext token:" << token << endl;
    if (token == 0) {
        cout << "[WARN] token is 0, callbacks will not be triggered, "
             << "check persist.rosen.rsclientmultiinstance.enabled = 1" << endl;
    }

    auto runner = AppExecFwk::EventRunner::Create(true);
    auto handler = make_shared<AppExecFwk::EventHandler>(runner);
    // useMultiInstance = true: attach the task runner to the rsUIContext under uni-render, so the
    // RS callback message is dispatched on this runner and the processed callback fires on it
    rsUiDirector->SetUITaskRunner(
        [handler](const function<void()>& task, uint32_t delay) { handler->PostTask(task, delay); },
        INSTANCE_ID_UNDEFINED, true);
    runner->Run();

    Init(rsUiDirector, rsUIContext);
    surfaceNode->AttachToDisplay(defaultScreenId);
    // nodes/animations are bound to the rsUIContext, flush its own transaction via the
    // per-instance RSUIDirector instead of the process-wide RSTransaction singleton
    rsUiDirector->SendMessages();
    sleep(1);

    // choose the run mode from stdin: 1 = 4-case verification (default), 2 = stress loop;
    // hdc shell without piped input hits EOF and falls back to verification
    cout << "\nselect mode, 1 = verify (default), 2 = stress test: " << endl;
    int mode = 1;
    if (!(cin >> mode)) {
        cout << "no stdin input, fall back to verify mode" << endl;
        mode = 1;
    }
    if (mode == STRESS_MODE) {
        RunStressTest(handler, rsUiDirector, rsUIContext);
    } else {
        RunVerifyCases(handler, rsUiDirector, rsUIContext);
    }

    RSInterfaces::GetInstance().UnRegisterUIContextMessageCallbacks();
    cout << "\nrs client ui context message callback demo end!" << endl;
    surfaceNode->SetVisible(false);
    // release the client-side node references with the final flush: the queued visibility command
    // holds its own reference, and every pump window (800ms) has long expired inside its case's
    // sleep(2), so no in-flight tick can dereference these nulls
    rootNode = nullptr;
    canvasNode = nullptr;
    surfaceNode = nullptr;
    rsUiDirector->SendMessages();
    sleep(1);
    return 0;
}
