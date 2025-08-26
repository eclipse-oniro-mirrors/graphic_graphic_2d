/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "rsrenderthreadclient_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "command/rs_node_showing_command.h"
#include "transaction/rs_render_thread_client.h"

namespace OHOS {
namespace Rosen {
namespace {
const uint8_t* DATA = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace

/*
 * describe: get data from outside untrusted data(DATA) which size is according to sizeof(T)
 * tips: only support basic type
 */
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (DATA == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

bool Init(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    DATA = data;
    g_size = size;
    g_pos = 0;
    return true;
}

bool DoCommitTransaction()
{
    // test
    auto renderThreadClient = RSIRenderClient::CreateRenderThreadClient();
    auto transactionData = std::make_unique<RSTransactionData>();
    renderThreadClient->CommitTransaction(transactionData);
    return true;
}

bool DoExecuteSynchronousTask()
{
    // test
    auto renderThreadClient = RSIRenderClient::CreateRenderThreadClient();
    auto task = std::make_shared<RSNodeGetShowingPropertyAndCancelAnimation>(0, nullptr);
    renderThreadClient->ExecuteSynchronousTask(task);
    return true;
}
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput()
{
    /* Run your code on data */
    OHOS::Rosen::DoCommitTransaction();
    OHOS::Rosen::DoExecuteSynchronousTask();
    return 0;
}