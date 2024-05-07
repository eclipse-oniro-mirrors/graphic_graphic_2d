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
#ifndef BLUR_CIRCLES_H
#define BLUR_CIRCLES_H
#include "../test_base.h"
#include <bits/alltypes.h>

class BlurCircles : public TestBase {
public:
    BlurCircles();
    ~BlurCircles() override;

protected:
    void OnTestFunction(OH_Drawing_Canvas *canvas) override;
    float ConvertRadiusToSigma(float radius);
};
#endif // BLUR_CIRCLES_GM_H
