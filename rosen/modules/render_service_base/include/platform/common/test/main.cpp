#include <iostream>
#include <windows.h>
#include "EventManager.h"

//int  main(int argv, char** argc) {
//	std::cout << "hhhhh" << std::endl;
//	return 0;
//}
using namespace OHOS::Rosen;

int main(int argv, char** argc) {
	std::cout << "hhhhhh " << std::endl;
	std::shared_ptr<BaseEventDetector> BaseEventDetectorPtr = BaseEventDetector::CreateRSTimeOutDetector(1000,"RS_COMPOSITION_TIMEOUT");
	SysEventManager::Instance().AddEvent(BaseEventDetectorPtr,5000);
	int count = 0;
	BaseEventDetectorPtr->SetLoopStartTag();
	while (count<1000)
	{
		SysEventManager::Instance().UpdateParam();
		Sleep(10);
		if (count == 500) {
			BaseEventDetectorPtr->SetLoopFinishTag();
		}
		count++;
	}

	SysEventManager::Instance().RemoveEvent(BaseEventDetectorPtr->GetStringId());
	return 0;
}