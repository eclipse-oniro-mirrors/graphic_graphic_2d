/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_COMMON_OPTIONAL_TRACE
#define RENDER_SERVICE_BASE_COMMON_OPTIONAL_TRACE

#include "foundation/graphic/graphic_2d/utils/log/rs_trace.h"
#include "securec.h"
#ifndef ROSEN_TRACE_DISABLE
#include "platform/common/rs_system_properties.h"
static inline int g_debugLevel = OHOS::Rosen::RSSystemProperties::GetDebugTraceLevel();

#define RS_OPTIONAL_TRACE_BEGIN_LEVEL(Level, fmt, ...)           \
    do {                                                         \
        if (UNLIKELY(g_debugLevel >= (Level))) {                 \
            RenderTrace::OptionalTraceStart(fmt, ##__VA_ARGS__); \
        }                                                        \
    } while (0)

#define RS_OPTIONAL_TRACE_END_LEVEL(Level)                       \
    do {                                                         \
        if (UNLIKELY(g_debugLevel >= (Level))) {                 \
            FinishTrace(HITRACE_TAG_GRAPHIC_AGP);                \
        }                                                        \
    } while (0)

#define RS_OPTIONAL_TRACE_BEGIN(name)                            \
    do {                                                         \
        if (Rosen::RSSystemProperties::GetDebugTraceEnabled()) { \
            RS_TRACE_BEGIN(name);                                \
        }                                                        \
    } while (0)

#define RS_OPTIONAL_TRACE_END()                                  \
    do {                                                         \
        if (Rosen::RSSystemProperties::GetDebugTraceEnabled()) { \
            RS_TRACE_END();                                      \
        }                                                        \
    } while (0)

#define RS_OPTIONAL_TRACE_NAME_FMT(fmt, ...)                                \
    do {                                                                    \
        if (Rosen::RSSystemProperties::GetDebugTraceEnabled()) {            \
            HITRACE_METER_FMT(HITRACE_TAG_GRAPHIC_AGP, fmt, ##__VA_ARGS__); \
        }                                                                   \
    } while (0)

#define RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(Level, fmt, ...)                   \
    do {                                                                    \
        if (Rosen::RSSystemProperties::GetDebugTraceLevel() >= Level) {     \
            HITRACE_METER_FMT(HITRACE_TAG_GRAPHIC_AGP, fmt, ##__VA_ARGS__); \
        }                                                                   \
    } while (0)

#define RS_APPOINTED_TRACE_BEGIN(node, name)                         \
    do {                                                             \
        if (Rosen::RSSystemProperties::GetDebugTraceEnabled() ||     \
            Rosen::RSSystemProperties::FindNodeInTargetList(node)) { \
            RS_TRACE_BEGIN(name);                                    \
        }                                                            \
    } while (0)

#define RS_APPOINTED_TRACE_END(node)                                 \
    do {                                                             \
        if (Rosen::RSSystemProperties::GetDebugTraceEnabled() ||     \
            Rosen::RSSystemProperties::FindNodeInTargetList(node)) { \
            RS_TRACE_END();                                          \
        }                                                            \
    } while (0)

#define RS_OPTIONAL_TRACE_NAME(name) RSOptionalTrace optionalTrace(name)

#define RS_OPTIONAL_TRACE_FUNC() RSOptionalTrace optionalTrace(__func__)

#define RS_PROCESS_TRACE(forceEnable, name) RSProcessTrace processTrace(forceEnable, name)

#define RS_OPTIONAL_TRACE_FMT(fmt, ...)                                                         \
    auto optionalFmtTrace = (UNLIKELY(Rosen::RSSystemProperties::GetDebugFmtTraceEnabled())) ?  \
                                std::make_unique<RSOptionalFmtTrace>(fmt, ##__VA_ARGS__) :      \
                                nullptr

class RenderTrace {
public:
    static void OptionalTraceStart(const char* fmt, ...)
    {
        va_list vaList;
        char buf[maxSize_];
        va_start(vaList, fmt);
        if (vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, vaList) < 0) {
            va_end(vaList);
            StartTrace(HITRACE_TAG_GRAPHIC_AGP, "length > 256, error");
            return;
        }
        va_end(vaList);
        StartTrace(HITRACE_TAG_GRAPHIC_AGP, buf);
    }
private:
    static const int maxSize_ = 256; // 256 Maximum length of a character string to be printed
};

class RSOptionalFmtTrace {
public:
    RSOptionalFmtTrace(const char* fmt, ...)
    {
        va_list vaList;
        va_start(vaList, fmt);
        StartFormatTrace(fmt, vaList);
        va_end(vaList);
    }
    ~RSOptionalFmtTrace()
    {
        FinishTrace(HITRACE_TAG_GRAPHIC_AGP); // 256 Maximum length of a character string to be printed
    }

    inline static void StartFormatTrace(const char* fmt, ...)
    {
        va_list vaList;
        char buf[maxSize_];
        va_start(vaList, fmt);
        if (vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, vaList) < 0) {
            va_end(vaList);
            StartTrace(HITRACE_TAG_GRAPHIC_AGP, "length > 256, error");
            return;
        }
        va_end(vaList);
        StartTrace(HITRACE_TAG_GRAPHIC_AGP, buf);
    }

private:
    constexpr static int maxSize_ = 256;
};

class RSOptionalTrace {
public:
    RSOptionalTrace(const std::string& traceStr)
    {
        debugTraceEnable_ = OHOS::Rosen::RSSystemProperties::GetDebugTraceEnabled();
        if (debugTraceEnable_) {
            RS_TRACE_BEGIN(traceStr);
        }
    }
    ~RSOptionalTrace()
    {
        if (debugTraceEnable_) {
            RS_TRACE_END();
        }
    }

private:
    bool debugTraceEnable_ = false;
};

class RSProcessTrace {
public:
    RSProcessTrace(bool forceEnable, const std::string& traceStr)
    {
        debugTraceEnable_ = OHOS::Rosen::RSSystemProperties::GetDebugTraceEnabled();
        forceEnable_ = forceEnable;
        if (debugTraceEnable_ || forceEnable_) {
            RS_TRACE_BEGIN(traceStr);
        }
    }
    ~RSProcessTrace()
    {
        if (debugTraceEnable_ || forceEnable_) {
            RS_TRACE_END();
        }
    }
private:
    bool debugTraceEnable_ = false;
    bool forceEnable_ = false;
};
#else
#define RS_OPTIONAL_TRACE_BEGIN_LEVEL(Level, fmt, ...)
#define RS_OPTIONAL_TRACE_END_LEVEL(Level)
#define RS_OPTIONAL_TRACE_BEGIN(name)
#define RS_OPTIONAL_TRACE_END()
#define RS_OPTIONAL_TRACE_NAME_FMT(fmt, ...)
#define RS_OPTIONAL_TRACE_FMT(fmt, ...)
#define RS_APPOINTED_TRACE_BEGIN(node, name)
#define RS_OPTIONAL_TRACE_NAME(name)
#define RS_OPTIONAL_TRACE_FUNC()
#define RS_PROCESS_TRACE(forceEnable, name)
#define RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(Level, fmt, ...) \
    do {                                                  \
        (void)TRACE_LEVEL_TWO;                            \
    } while (0)
#endif // ROSEN_TRACE_DISABLE
#endif // RENDER_SERVICE_BASE_COMMON_OPTIONAL_TRACE