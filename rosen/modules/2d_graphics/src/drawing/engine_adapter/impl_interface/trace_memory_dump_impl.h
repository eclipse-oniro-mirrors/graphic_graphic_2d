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

#ifndef TRACE_MEMORY_DUMP_IMPL_H
#define TRACE_MEMORY_DUMP_IMPL_H

#include <chrono>

#include "base_impl.h"
#include "memory/rs_dfx_string.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class TraceMemoryDumpImpl : public BaseImpl {
public:
    TraceMemoryDumpImpl(const char* categoryKey, bool itemizeType) {};
    ~TraceMemoryDumpImpl() override {};

    virtual void DumpNumericValue(const char* dumpName, const char* valueName, const char* units, uint64_t value) = 0;

    virtual void DumpStringValue(const char* dumpName, const char* valueName, const char* value) = 0;

    virtual void LogOutput(OHOS::Rosen::DfxString& log) = 0;

    virtual void LogTotals(OHOS::Rosen::DfxString& log) = 0;

    virtual float GetGpuMemorySizeInMB() const = 0;

    virtual float GetGLMemorySize() const = 0;
};
}
}
}
#endif // TRACE_MEMORY_DUMP_IMPL_H