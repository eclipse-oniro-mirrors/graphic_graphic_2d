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
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "mock.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_device.h"

namespace OHOS {
namespace Rosen {

bool g_ProcessOfflineSurfaceNull = false;
bool g_GetOfflineConfigNull = false;
bool g_DlopenNull = false;
bool g_InitOfflineNull = false;
bool g_DeInitOfflineNull = false;
bool g_InitPrevalidateNull = false;
bool g_InitPrevalidateFailed = false;
bool g_GetOfflineOutputFenceFailed = false;

int32_t MockProcessOfflineSurface(const OfflineProcessInputInfo &inputInfo)
{
    return 0;
}

int32_t MockGetOfflineConfig(NodeId nodeId, OfflineProcessOutputInfo &outputInfo)
{
    return 0;
}

int32_t MockInitOffline()
{
    return 0;
}

void MockDeInitOffline()
{
}

int32_t MockGetOfflineOutputFence(int32_t &outputFence)
{
    outputFence = -1;
    return 0;
}

int32_t MockInitPrevalidate()
{
    if (g_InitPrevalidateFailed) {
        return -1;
    }
    return 0;
}

extern "C" void *dlsym(void *handle, const char *symbol)
{
    if (strcmp(symbol, "ProcessOfflineSurface") == 0) {
        if (g_ProcessOfflineSurfaceNull) {
            return nullptr;
        }
        return reinterpret_cast<void *>(MockProcessOfflineSurface);
    }
    if (strcmp(symbol, "GetOfflineConfig") == 0) {
        if (g_GetOfflineConfigNull) {
            return nullptr;
        }
        return reinterpret_cast<void *>(MockGetOfflineConfig);
    }
    if (strcmp(symbol, "InitOfflineResource") == 0) {
        if (g_InitOfflineNull) {
            return nullptr;
        }
        return reinterpret_cast<void *>(MockInitOffline);
    }
    if (strcmp(symbol, "DeInitOfflineResource") == 0) {
        if (g_DeInitOfflineNull) {
            return nullptr;
        }
        return reinterpret_cast<void *>(MockDeInitOffline);
    }
    if (strcmp(symbol, "InitPrevalidate") == 0) {
        if (g_InitPrevalidateNull) {
            return nullptr;
        }
        return reinterpret_cast<void *>(MockInitPrevalidate);
    }
    if (strcmp(symbol, "GetOfflineOutputFence") == 0) {
        if (g_GetOfflineOutputFenceFailed) {
            return nullptr;
        }
        return reinterpret_cast<void *>(MockGetOfflineOutputFence);
    }
    return NULL;
}

extern "C" void *dlopen(const char *filename, int flags)
{
    if (strcmp(filename, "libprevalidate_client.z.so") == 0) {
        if (g_DlopenNull) {
            return nullptr;
        }
        return reinterpret_cast<void *>(0x1234);
    }
    return NULL;
}

extern "C" int dlclose(void *handle)
{
    if (handle == reinterpret_cast<void *>(0x1234)) {
        return 0;
    }
    return -1;
}

}  // namespace Rosen
}  // namespace OHOS