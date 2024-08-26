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

#ifndef HDI_BACKEND_HDI_LOG_H
#define HDI_BACKEND_HDI_LOG_H

#include <hilog/log.h>

namespace OHOS {
namespace Rosen {

namespace {
// The "0xD001400" is the domain ID for graphic module that alloted by the OS.
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD001400
#undef LOG_TAG
#define LOG_TAG "Composer"
}

#define C_HLOG(func, fmt, ...) \
    func(LOG_CORE, "%{public}s: " fmt, __func__, ##__VA_ARGS__)

#define HLOGD(fmt, ...) C_HLOG(HILOG_DEBUG, fmt, ##__VA_ARGS__)
#define HLOGI(fmt, ...) C_HLOG(HILOG_INFO, fmt, ##__VA_ARGS__)
#define HLOGW(fmt, ...) C_HLOG(HILOG_WARN, fmt, ##__VA_ARGS__)
#define HLOGE(fmt, ...) C_HLOG(HILOG_ERROR, fmt, ##__VA_ARGS__)
} // namespace Rosen
} // namespace OHOS

#endif // HDI_BACKEND_HDI_LOG_H