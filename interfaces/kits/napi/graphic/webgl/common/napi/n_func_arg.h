/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef ROSENRENDER_ROSEN_FUNC_ARG
#define ROSENRENDER_ROSEN_FUNC_ARG

#include <functional>
#include <map>
#include "napi/n_val.h"
#include "napi/uni_header.h"

namespace OHOS {
namespace Rosen {
enum NARG_CNT {
    ZERO = 0,
    ONE = 1,
    TWO = 2,
    THREE = 3,
    FOUR = 4,
    FIVE = 5,
    SIX = 6,
    SEVEN = 7,
    EIGHT = 8,
    NINE = 9,
    TEN = 10,
    ELEVEN = 11,
    TWELVE = 12,
};

enum NARG_POS {
    FIRST = 0,
    SECOND = 1,
    THIRD = 2,
    FOURTH = 3,
    FIFTH = 4,
    SIXTH = 5,
    SEVENTH = 6,
    EIGHTH = 7,
    NINTH = 8,
    TENTH = 9,
    ELEVENTH = 10,
    TWELVETH = 11,
};

class NFuncArg final {
public:
    NFuncArg(napi_env env, napi_callback_info info);
    virtual ~NFuncArg();

    bool InitArgs(size_t argc);
    bool InitArgs(size_t minArgc, size_t maxArgc);
    size_t GetArgc() const;
    size_t GetMaxArgc(void) const;
    napi_value GetThisVar() const;
    napi_value operator[](size_t argPos) const;
    napi_value GetArg(size_t argPos) const;

private:
    bool InitArgs(std::function<bool()> argcChecker);
    void SetArgc(size_t argc);
    void SetThisVar(napi_value thisVar);
    void SetMaxArgc(size_t maxArgc);
    napi_env env_ = nullptr;
    napi_callback_info info_ = nullptr;
    size_t argc_ = 0;
    size_t maxArgc_ = 0;
    std::unique_ptr<napi_value[]> argv_ = {nullptr};
    napi_value thisVar_ = nullptr;
};
} // namespace Rosen
} // namespace OHOS
#endif // ROSENRENDER_ROSEN_FUNC_ARG
