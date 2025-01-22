/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */
#include "dtk_test_base.h"
#include <iostream>
#include <message_parcel.h>
#include <sstream>
#include <string>
#include <surface.h>

#include "transaction/rs_transaction.h"
#include "wm/window.h"

namespace OHOS {
namespace Rosen {
void TestBase::SetTestCount(int testCount)
{
    testCount_ = testCount;
}

void TestBase::SetCanvas(TestPlaybackCanvas* canvas)
{
    playbackCanvas_ = canvas;
}

void TestBase::SetSurface(Drawing::Surface* surface)
{
    mSurface = surface;
}

void TestBase::AddTestBrush(bool isAA)
{
    Drawing::Brush brush;
    brush.SetColor(0xFFFF0000);
    brush.SetAntiAlias(isAA);
    playbackCanvas_->AttachBrush(brush);
}

void TestBase::AddTestPen(bool isAA)
{
    Drawing::Pen pen;
    pen.SetColor(0xFFFF0000);
    pen.SetWidth(10.0f);
    pen.SetAntiAlias(isAA);
    playbackCanvas_->AttachPen(pen);
}

void TestBase::AddTestPen(bool isAA, float width)
{
    Drawing::Pen pen;
    pen.SetColor(0xFFFF0000);
    pen.SetWidth(width);
    pen.SetAntiAlias(isAA);
    playbackCanvas_->AttachPen(pen);
}

void TestBase::AddTestPen(bool isAA, Drawing::Pen::JoinStyle joinStyle)
{
    Drawing::Pen pen;
    pen.SetColor(0xFFFF0000);
    pen.SetWidth(10.0f);
    pen.SetAntiAlias(isAA);
    pen.SetJoinStyle(joinStyle);
    playbackCanvas_->AttachPen(pen);
}
void TestBase::AddTestPen(bool isAA, Drawing::Pen::CapStyle capStyle)
{
    Drawing::Pen pen;
    pen.SetColor(0xFFFF0000);
    pen.SetWidth(10.0f);
    pen.SetAntiAlias(isAA);
    pen.SetCapStyle(capStyle);
    playbackCanvas_->AttachPen(pen);
}

void TestBase::AddTestPen(bool isAA, Drawing::Pen::CapStyle capStyle, Drawing::Pen::JoinStyle joinStyle)
{
    Drawing::Pen pen;
    pen.SetColor(0xFFFF0000);
    pen.SetWidth(10.0f);
    pen.SetAntiAlias(isAA);
    pen.SetCapStyle(capStyle);
    pen.SetJoinStyle(joinStyle);
    playbackCanvas_->AttachPen(pen);
}

void TestBase::AddTestBrushAndPen(bool isAA)
{
    AddTestBrush(isAA);
    AddTestPen(isAA);
}

void TestBase::ClearTestBrush()
{
    playbackCanvas_->DetachBrush();
}

void TestBase::ClearTestPen()
{
    playbackCanvas_->DetachPen();
}

void TestBase::ClearTestBrushAndPen()
{
    playbackCanvas_->DetachBrush();
    playbackCanvas_->DetachPen();
}

void TestBase::Recording()
{
    OnRecording();
}

void TestBase::Init(std::shared_ptr<RSUIDirector> rsUiDirector, int width, int height)
{
    std::cout << "rs pixelmap demo Init Rosen Backend!" << std::endl;
    rootNode_ = RSRootNode::Create();
    rootNode_->SetBounds(0, 0, width, height);
    rootNode_->SetFrame(0, 0, width, height);
    rootNode_->SetBackgroundColor(Drawing::Color::COLOR_WHITE);
    rsUiDirector->SetRoot(rootNode_->GetId());
    canvasNode_ = RSCanvasNode::Create();
    canvasNode_->SetFrame(0, 0, width, height);
    rootNode_->AddChild(canvasNode_, -1);
}

std::shared_ptr<Drawing::Image> TestBase::OnSurfaceCapture(std::shared_ptr<Media::PixelMap> pixelmap)
{
    if (pixelmap == nullptr)
    {
        std::cout << "RSUIDirector::LocalCapture failed to get pixelmap, return nullptr" << std::endl;
        return nullptr;
    }
    std::cout << "rs local surface demo drawImage" << std::endl;

    Drawing::Bitmap bitmap;
    auto skii = SkImageInfo::Make(pixelmap->GetWidth(), pixelmap->GetHeight(), SkColorType::kRGBA_8888_SkColorType,
        SkAlphaType::kPremul_SkAlphaType);
    auto ddgr = Drawing::ImageInfo(pixelmap->GetWidth(), pixelmap->GetHeight(), Drawing::ColorType::COLORTYPE_RGBA_8888,
        Drawing::AlphaType::ALPHATYPE_PREMUL);
    if (!bitmap.InstallPixels(ddgr, (void*)pixelmap->GetPixels(), skii.minRowBytes64())) {
        std::cout << __func__ << "installPixels failed" << std::endl;
        return nullptr;
    }
    auto image = bitmap.MakeImage();
    return image;
}

std::shared_ptr<Drawing::Image> TestBase::MakeImage(int w, int h, MakeImageFunc func)
{
    std::string demoName = "imagefilters";
    RSSystemProperties::GetUniRenderEnabled();
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowType(WindowType::WINDOW_TYPE_FLOAT);
    option->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    option->SetWindowRect({0, 0, w, h});
    auto window = Window::Create(demoName, option);
    window->Show();
    usleep(30000); // sleep 30000 microsecond

    auto rect = window->GetRect();
    while (rect.width_ == 0 && rect.height_ == 0) {
        std::cout << "rs demo create new window failed: " << rect.width_ << " " << rect.height_ << std::endl;
        window->Hide();
        window->Destroy();
        window = Window::Create(demoName, option);
        window->Show();
        usleep(30000); // sleep 30000 microsecond
        rect = window->GetRect();
    }
    std::cout << "rs demo create new window success: " << rect.width_ << " " << rect.height_ << std::endl;
    auto surfaceNode = window->GetSurfaceNode();

    auto rsUiDirector = RSUIDirector::Create();
    rsUiDirector->Init();
    RSTransaction::FlushImplicitTransaction();

    rsUiDirector->SetRSSurfaceNode(surfaceNode);
    Init(rsUiDirector, rect.width_, rect.height_);
    rsUiDirector->SendMessages();

    auto canvas = canvasNode_->BeginRecording(rect.width_, rect.height_);
    auto newCanvas = (TestPlaybackCanvas*)(canvas);

    // core code;
    func(newCanvas, w, h);

    canvasNode_->FinishRecording();
    rsUiDirector->SendMessages();
    usleep(16666); // sleep 16666 microsecond
    usleep(50000); // sleep 50000 microsecond
    auto newImage = OnSurfaceCapture(window->Snapshot());
    window->Hide();
    window->Destroy();
    return newImage;
}

std::shared_ptr<Drawing::Image> TestBase::GetEffectTestImage(const std::string& pathName)
{
    if (auto iter = effectTestImageMap_.find(pathName);
        iter != effectTestImageMap_.end()) {
        return iter->second;
    }
    auto image = std::make_shared<Drawing::Image>();
    auto encodeDate = Drawing::Data::MakeFromFileName(pathName.c_str());
    image->MakeFromEncoded(encodeDate);
    effectTestImageMap_[pathName] = image;
    return image;
}

std::shared_ptr<Drawing::Surface> TestBase::GetNewColorSpaceSurface()
{
    if (csSurface_) {
        return csSurface_;
    }
    auto colorspace = Drawing::ColorSpace::CreateRGB(Drawing::CMSTransferFuncType::DOT2,
        Drawing::CMSMatrixType::ADOBE_RGB);
    // 1000 is the width of the panda1000 picture which we used
    Drawing::ImageInfo imageInfo(1000, 1000, Drawing::ColorType::COLORTYPE_RGBA_8888,
        Drawing::AlphaType::ALPHATYPE_PREMUL, colorspace);
    auto context = playbackCanvas_->GetGPUContext();
    csSurface_ = Drawing::Surface::MakeRenderTarget(context.get(), false, imageInfo);
    return csSurface_;
}

std::shared_ptr<Drawing::RuntimeEffect> TestBase::GetTestRuntimeEffectForShader(const char* glsl)
{
    std::hash<std::string> hasher;
    size_t hash = hasher(glsl);
    if (auto iter = runtimeEffectMap_.find(hash);
        iter != runtimeEffectMap_.end()) {
        return iter->second;
    }
    std::shared_ptr<Drawing::RuntimeEffect> runtimeEffect =
        Drawing::RuntimeEffect::CreateForShader(glsl);
    if (runtimeEffect) {
        runtimeEffectMap_[hash] = runtimeEffect;
    }
    return runtimeEffect;
}

std::shared_ptr<Drawing::RuntimeEffect> TestBase::GetTestRuntimeEffectForBlender(const char* glsl)
{
    std::hash<std::string> hasher;
    size_t hash = hasher(glsl);
    if (auto iter = runtimeEffectMap_.find(hash);
        iter != runtimeEffectMap_.end()) {
        return iter->second;
    }
    std::shared_ptr<Drawing::RuntimeEffect> runtimeEffect =
        Drawing::RuntimeEffect::CreateForBlender(glsl);
    if (runtimeEffect) {
        runtimeEffectMap_[hash] = runtimeEffect;
    }
    return runtimeEffect;
}
} // namespace Rosen
} // namespace OHOS