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
#include <event_handler.h>
#include <iostream>

#include "animation/rs_animation_timing_curve.h"
#include "animation/rs_animation_timing_protocol.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_root_node.h"
#include "ui/rs_surface_node.h"
#include "ui/rs_ui_director.h"

using namespace OHOS;
using namespace OHOS::Rosen;
using namespace std;

constexpr uint32_t ANIMATION_DURATION_MS = 500;
constexpr uint32_t STAGE_WAIT_SECONDS = 3;
constexpr int32_t SCREEN_WIDTH = 1260;
constexpr int32_t SCREEN_HEIGHT = 2720;

shared_ptr<RSNode> rootNode;
shared_ptr<RSCanvasNode> canvasNode;
shared_ptr<RSSurfaceNode> surfaceNode;

// case 1/2/3 counters, received fires on the IPC receiving thread,
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

// The animation is created by RSNode::Animate with the rsUIContext, so the animation command carries
// the context token and runs in the render service process. When it finishes, RS sends the
// RSAnimationCallback command (with the same token) back to this process, it enters uiContextCmdMap
// in RSUIDirector::ProcessMessages and passively triggers the registered callbacks.
void StartAnimatedProperty(const shared_ptr<RSUIContext>& rsUIContext, const char* tag)
{
    RSAnimationTimingProtocol protocol;
    protocol.SetDuration(ANIMATION_DURATION_MS);
    auto curve = RSAnimationTimingCurve::CreateCubicCurve(0.2f, 0.0f, 0.2f, 1.0f);
    auto propertyCallback = []() {
        canvasNode->SetBounds(200, 400, 600, 600);
        canvasNode->SetFrame(200, 400, 600, 600);
    };
    auto finishCallback = [tag]() {
        // proves the RS->client callback message really arrived
        cout << "[RSNode::Animate] " << tag << " finish callback (from RS process)" << endl;
    };
    RSNode::Animate(rsUIContext, protocol, curve, propertyCallback, finishCallback);
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

    cout << "\n===== case 1: register callbacks, passively triggered by RS animation callback =====" << endl;
    RSInterfaces::GetInstance().RegisterUIContextMessageCallbacks(OnMessageReceived, OnMessageProcessed);
    StartAnimatedProperty(rsUIContext, "case1");
    rsUiDirector->SendMessages();
    sleep(STAGE_WAIT_SECONDS);
    cout << "case1 " << ((g_receivedCount > 0 && g_processedCount > 0) ? "PASS" : "FAIL")
         << ", receivedCount:" << g_receivedCount << ", processedCount:" << g_processedCount << endl;

    cout << "\n===== case 2: unregister, callbacks should NOT be triggered =====" << endl;
    RSInterfaces::GetInstance().UnRegisterUIContextMessageCallbacks();
    uint32_t recvBefore = g_receivedCount;
    uint32_t procBefore = g_processedCount;
    StartAnimatedProperty(rsUIContext, "case2");
    rsUiDirector->SendMessages();
    sleep(STAGE_WAIT_SECONDS);
    cout << "case2 " << ((g_receivedCount == recvBefore && g_processedCount == procBefore) ? "PASS" : "FAIL")
         << ", receivedCount:" << g_receivedCount << "/" << recvBefore << ", processedCount:" << g_processedCount << "/"
         << procBefore << endl;

    cout << "\n===== case 3: register nullptr callbacks, should NOT be triggered and no crash =====" << endl;
    RSInterfaces::GetInstance().RegisterUIContextMessageCallbacks(nullptr, nullptr);
    recvBefore = g_receivedCount;
    procBefore = g_processedCount;
    StartAnimatedProperty(rsUIContext, "case3");
    rsUiDirector->SendMessages();
    sleep(STAGE_WAIT_SECONDS);
    cout << "case3 " << ((g_receivedCount == recvBefore && g_processedCount == procBefore) ? "PASS" : "FAIL")
         << ", receivedCount:" << g_receivedCount << "/" << recvBefore << ", processedCount:" << g_processedCount << "/"
         << procBefore << endl;

    RSInterfaces::GetInstance().UnRegisterUIContextMessageCallbacks();
    cout << "\nrs client ui context message callback demo end!" << endl;
    surfaceNode->SetVisible(false);
    rsUiDirector->SendMessages();
    sleep(1);
    return 0;
}
