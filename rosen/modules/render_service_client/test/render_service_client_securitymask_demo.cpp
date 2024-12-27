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

#include <iostream>
#include "image_source.h"
#include "pixel_map.h"
#include "transaction/rs_interfaces.h"

using namespace OHOS;
using namespace OHOS::Rosen;
using namespace std;

shared_ptr<Media::PixelMap> DecodePixelMap(const string& pathName, const Media::AllocatorType& allocatorType)
{
    uint32_t errCode = 0;
    unique_ptr<Media::ImageSource> imageSource =
        Media::ImageSource::CreateImageSource(pathName, Media::SourceOptions(), errCode);
    if (imageSource == nullptr || errCode != 0) {
        cout << "imageSource : " << (imageSource != nullptr) << ", err:" << errCode << endl;
        return nullptr;
    }

    Media::DecodeOptions decodeOpt;
    decodeOpt.allocatorType = allocatorType;
    shared_ptr<Media::PixelMap> pixelmap = imageSource->CreatePixelMap(decodeOpt, errCode);
    if (pixelmap == nullptr || errCode != 0) {
        cout << "pixelmap == nullptr, err:" << errCode << endl;
        return nullptr;
    }
    return pixelmap;
}
int main()
{
    auto allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    shared_ptr<Media::PixelMap> bgpixelmap = DecodePixelMap("/data/bgPic.jpg", allocatorType);
    ScreenId virtualScreenId;
    uint32_t open;
    int32_t ret;

    cout << "SecurityMask interface." << endl;
    cout << "Enter: ";
    cin >> open;
    cout << "ScreenId: ";
    cin >> virtualScreenId;

    if (open == 1) {
        ret = RSInterfaces::GetInstance().SetVirtualScreenSecurityMask(virtualScreenId, bgpixelmap);
    } else {
        ret = RSInterfaces::GetInstance().SetVirtualScreenSecurityMask(virtualScreenId, nullptr);
    }

    if (ret) {
        cout << "SetSecurityMask Success."<< endl;
    }
    return 0;
}