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

#include "rs_profiler_utils.h"

#include <chrono>
#include <sstream>

#ifndef REPLAY_TOOL_CLIENT
#include "rs_profiler_base.h"
#endif

namespace OHOS::Rosen::Utils {

#ifndef REPLAY_TOOL_CLIENT

uint64_t RawNowNano()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

uint64_t NowNano()
{
    // return std::chrono::duration<double>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    //  steady_clock is used everywhere for some reason
    uint64_t curTimeNano = RawNowNano();
    curTimeNano = RSProfilerBase::TimePauseApply(curTimeNano);
    return curTimeNano;
}

#else

uint64_t RawNowNano()
{
    return 0;
}

uint64_t NowNano()
{
    return 0;
}

#endif

double Now()
{
    return (static_cast<double>(NowNano())) / 1'000'000'000;
}

std::vector<std::string> Split(const std::string& input)
{
    using namespace std;
    istringstream iss(input);
    vector<string> parts { istream_iterator<string> { iss }, istream_iterator<string> {} };
    return parts;
}

} // namespace OHOS::Rosen::Utils