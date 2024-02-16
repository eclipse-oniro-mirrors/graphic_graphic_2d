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

#ifndef RS_PROFILER_UTILS_H
#define RS_PROFILER_UTILS_H

#include <chrono>
#include <string>
#include <vector>

// expansion macro for enum value definition
#define ENUM_VALUE(name) name,

// expansion macro for enum to string conversion
#define ENUM_CASE(name) \
    case T::name:       \
        return #name;

#define DEFINE_ENUM(EnumName, ENUM_DEF)             \
    enum class EnumName { ENUM_DEF(ENUM_VALUE) };   \
    inline std::string str(EnumName value)          \
    {                                               \
        using T = EnumName;                         \
        switch (value) {                            \
            ENUM_DEF(ENUM_CASE)                     \
            default:                                \
                return "unknown";                   \
        }                                           \
    }
    
#define DEFINE_ENUM_WITH_TYPE(EnumName, UnderlyingType, ENUM_DEF)   \
    enum EnumName : UnderlyingType { ENUM_DEF(ENUM_VALUE) };        \
    inline std::string str(EnumName value)                          \
    {                                                               \
        using T = EnumName;                                         \
        switch (value) {                                            \
            ENUM_DEF(ENUM_CASE)                                     \
            default:                                                \
                return "unknown";                                   \
        }                                                           \
    }

#define HGM_EFUNC OHOS::HiviewDFX::HiLog::Error
#define HGM_CPRINTF(func, fmt, ...) func({ LOG_CORE, 0xD001400, "RRI2D" }, fmt, ##__VA_ARGS__)
#define HGM_LOGE(fmt, ...) HGM_CPRINTF(HGM_EFUNC, fmt, ##__VA_ARGS__)

namespace OHOS::Rosen::Utils {

uint64_t RawNowNano();
uint64_t NowNano();
double Now();
std::vector<std::string> Split(const std::string& input);

} // namespace OHOS::Rosen::Utils

#endif // RS_PROFILER_UTILS_H