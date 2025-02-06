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

#include "touch_screen.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr std::string_view TOUCHSCREEN_WRAPPER_PATH = "../../vendor/lib64/chipsetsdk/libhw_touchscreen.default.so";
} // namespace

TouchScreen::TouchScreen() {}
TouchScreen::~TouchScreen()
{
    if (touchScreenHandle_ != nullptr) {
        dlclose(touchScreenHandle_);
        touchScreenHandle_ = nullptr;
        setFeatureConfigHandle_ = nullptr;
        setAftConfigHandle_ = nullptr;
    }
}

void TouchScreen::InitTouchScreen()
{
    touchScreenHandle_ = dlopen(TOUCHSCREEN_WRAPPER_PATH.data(), RTLD_NOW);
    if (touchScreenHandle_ == nullptr) {
        RS_LOGE("libhw_touchscreen.default.so was not loaded, error: %{public}s", dlerror());
        return;
    }

    GetHandleBySymbol(setFeatureConfigHandle_, "ts_set_feature_config");
    GetHandleBySymbol(setAftConfigHandle_, "ts_set_aft_config");
}
} // namespace Rosen
} // namespace OHOS
