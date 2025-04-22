/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "skia_document.h"

#include "include/core/SkSerialProcs.h"
#include "tools/SkSharingProc.h"
#ifdef USE_M133_SKIA
#include "include/docs/SkMultiPictureDocument.h"
#else
#include "src/utils/SkMultiPictureDocument.h"
#endif

#include "skia_document.h"
#include "skia_file_w_stream.h"
#include "skia_serial_procs.h"
#include "skia_sharing_serial_context.h"
#ifdef USE_M133_SKIA
#include "include/core/SkTypeface.h"
#endif

#include "draw/canvas.h"
#include "skia_canvas.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

SkiaDocument::SkiaDocument(sk_sp<SkDocument> skDocument) noexcept : skDocument_(skDocument) {}

std::shared_ptr<Document> SkiaDocument::MakeMultiPictureDocument(
    FileWStream* fileStream, SerialProcs* procs, std::unique_ptr<Drawing::SharingSerialContext>& serialContext)
{
    auto skiaSharingSerialContext = serialContext->GetImpl<SkiaSharingSerialContext>();
    std::unique_ptr<SkSharingSerialContext>& serialContext_ = skiaSharingSerialContext->GetSkSharingSerialContext();
    auto skProc = procs->GetImpl<SkiaSerialProcs>()->GetSkSerialProcs();
    skProc->fImageProc = SkSharingSerialContext::serializeImage;
    skProc->fImageCtx = serialContext_.get();
    skProc->fTypefaceProc = [](SkTypeface* tf, void* ctx) {
        return tf->serialize(SkTypeface::SerializeBehavior::kDoIncludeData);
    };
    SkFILEWStream* dst = fileStream->GetImpl<SkiaFileWStream>()->GetSkFileWStream();
#ifdef USE_M133_SKIA
    auto skDocument = SkMultiPictureDocument::Make(dst, skProc, [sharingCtx = serialContext_.get()]
    (const SkPicture* pic) {
        SkSharingSerialContext::collectNonTextureImagesFromPicture(pic, sharingCtx);
    });
#else
    auto skDocument = SkMakeMultiPictureDocument(dst, skProc, [sharingCtx = serialContext_.get()]
        (const SkPicture* pic) {
        SkSharingSerialContext::collectNonTextureImagesFromPicture(pic, sharingCtx);
    });
#endif
    std::shared_ptr<DocumentImpl> documentImpl = std::make_shared<SkiaDocument>(skDocument);
    return std::make_shared<Document>(documentImpl);
}

const sk_sp<SkDocument> SkiaDocument::GetSkiaDocument() const
{
    return skDocument_;
}

std::shared_ptr<Canvas> SkiaDocument::BeginPage(float width, float height)
{
    if (skDocument_ == nullptr) {
        return nullptr;
    }
    auto skCanvas = skDocument_->beginPage(width, height);
    auto canvas = std::make_shared<Drawing::Canvas>();
    auto skiaCavas = canvas->GetImpl<SkiaCanvas>();
    if (skiaCavas == nullptr) {
        return nullptr;
    }
    skiaCavas->ImportSkCanvas(skCanvas);
    return canvas;
}

void SkiaDocument::EndPage()
{
    if (skDocument_ == nullptr) {
        return;
    }
    skDocument_->endPage();
}

void SkiaDocument::Close()
{
    if (skDocument_ == nullptr) {
        return;
    }
    skDocument_->close();
}
} // Drawing
} // Rosen
} // OHOS
