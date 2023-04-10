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

#ifndef ROSEN_MODULES_TEXGINE_EXPORT_TEXGINE_UTILS_TRACE_H
#define ROSEN_MODULES_TEXGINE_EXPORT_TEXGINE_UTILS_TRACE_H

#include <string>

namespace OHOS{
namespace TextEngine {
class ScopedTrace;

class Trace {
public:
    static void Start(const std::string &proc);
    static void Finish();
    static void Count(const std::string &key, int val);
    static void Disable();
};

class ScopedTrace {
public:
    ScopedTrace(const std::string &proc)
    {
        Trace::Start(proc);
    }

    ~ScopedTrace()
    {
        Finish();
    }

    void Finish()
    {
        if (isFinished == false) {
            isFinished = true;
            Trace::Finish();
        }
    }

private:
    bool isFinished = false;
};
} // namespace TextEngine
} // namespace OHOS

#endif // ROSEN_MODULES_TEXGINE_EXPORT_TEXGINE_UTILS_TRACE_H
