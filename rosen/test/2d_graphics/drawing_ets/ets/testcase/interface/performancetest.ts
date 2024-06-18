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

import drawing from "@ohos.graphics.drawing";
import common2D from "@ohos.graphics.common2D";
import {TestBase, StyleType} from '../../pages/testbase';
import globalThis from '../../utils/globalThis'
import image from '@ohos.multimedia.image';

export class PerformanceCanvasDrawRect extends TestBase {
  public constructor(styleType: number = StyleType.DRAW_STYLE_NONE){
    super();
    this.styleType_ = styleType;
  }
  public OnTestPerformance(canvas: drawing.Canvas) {
    for (let i = 0; i < this.testCount_; i++) {
      canvas.drawRect(0, 0, 100, 100);
    }
  }
}

export class PerformanceCanvasDrawCircle extends TestBase {
  public constructor(styleType: number = StyleType.DRAW_STYLE_NONE){
    super();
    this.styleType_ = styleType;
  }
  public OnTestPerformance(canvas: drawing.Canvas) {
    for (let i = 0; i < this.testCount_; i++) {
      canvas.drawCircle(200, 200, 100);
    }
  }
}

export class PerformanceCanvasDrawLine extends TestBase {
  public constructor(styleType: number = StyleType.DRAW_STYLE_NONE){
    super();
    this.styleType_ = styleType;
  }
  public OnTestPerformance(canvas: drawing.Canvas) {
    for (let i = 0; i < this.testCount_; i++) {
      canvas.drawLine(0, 0, 100, 100);
    }
  }
}

export class PerformanceCanvasDrawPath extends TestBase {
  public constructor(styleType: number = StyleType.DRAW_STYLE_NONE){
    super();
    this.styleType_ = styleType;
  }
  public OnTestPerformance(canvas: drawing.Canvas) {
    let path = new drawing.Path;
    path.arcTo(0, 0, 100, 100, 0, 180)
    for (let i = 0; i < this.testCount_; i++) {
      canvas.drawPath(path);
    }
  }
}

export class PerformanceCanvasDrawTextBlob extends TestBase {
  public constructor(styleType: number = StyleType.DRAW_STYLE_NONE){
    super();
    this.styleType_ = styleType;
  }
  public OnTestPerformance(canvas: drawing.Canvas) {
    let text : string = 'textblob';
    const font : drawing.Font = new drawing.Font();
    font.setSize(20)
    const textBlob = drawing.TextBlob.makeFromString(text, font, drawing.TextEncoding.TEXT_ENCODING_UTF8);
    for (let i = 0; i < this.testCount_; i++) {
      canvas.drawTextBlob(textBlob, 0, 0);
    }
  }
}

export class PerformanceCanvasPoint extends TestBase {
  public constructor(styleType: number = StyleType.DRAW_STYLE_NONE){
    super();
    this.styleType_ = styleType;
  }
  public OnTestPerformance(canvas: drawing.Canvas) {
    for (let i = 0; i < this.testCount_; i++) {
      canvas.drawPoint(50, 50);
    }
  }
}