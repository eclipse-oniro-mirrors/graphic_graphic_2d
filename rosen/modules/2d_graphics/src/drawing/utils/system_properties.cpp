/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <parameter.h>
#include <parameters.h>
#include "utils/system_properties.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

bool SystemProperties::GetHMSymbolEnable()
{
    static bool isHMSymbolEnable =
        (std::atoi(system::GetParameter("persist.sys.graphic.hmsymbolenable", "1").c_str()) != 0);
    return isHMSymbolEnable;
}

#if (defined (ACE_ENABLE_GL) && defined (ACE_ENABLE_VK)) || (defined (RS_ENABLE_GL) && defined (RS_ENABLE_VK))
const GpuApiType SystemProperties::systemGpuApiType_ = SystemProperties::GetSystemGraphicGpuType();
#elif defined (ACE_ENABLE_GL) || defined (RS_ENABLE_GL)
const GpuApiType SystemProperties::systemGpuApiType_ = GpuApiType::OPENGL;
#else
const GpuApiType SystemProperties::systemGpuApiType_ = GpuApiType::VULKAN;
#endif

#ifdef ROSEN_OHOS
bool SystemProperties::IsVkImageDfxEnabled()
{
    static const bool dfxEnabled =
        std::atoi(OHOS::system::GetParameter("persist.sys.graphic.openVkImageMemoryDfx", "1").c_str()) != 0;
    return dfxEnabled;
}
#endif
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS