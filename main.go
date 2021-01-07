// +build windows
package main

// #include <stdio.h>
// #include <errno.h>
import "C"

import (
	"fmt"
	"log"
	"time"
	"unsafe"

	"github.com/gamexg/gowindows"
	"golang.org/x/sys/windows"
)

const FIREWALL_SUBLAYER_NAMEW = "MyFWP1"
const FIREWALL_SERVICE_NAMEW = "MyFWP1.1"

func main() {
	err := StartEngine()
	if err != nil {
		panic(err)
	}

	log.Println("Nhấn Enter để kết thúc chương trình")
	var s string
	fmt.Scanln(&s)
}

func StartEngine() error {
	engineHandle := gowindows.Handle(0)

	session := gowindows.FwpmSession0{
		Flags: gowindows.FWPM_SESSION_FLAG_DYNAMIC,
	}

	err := gowindows.FwpmEngineOpen0("", gowindows.RPC_C_AUTHN_WINNT, nil, &session, &engineHandle)
	if err != nil {
		return fmt.Errorf("FwpmEngineOpen0,%v", err)
	}
	/*err := gowindows.FWPM_NET_EVENT_CLASSIFY_DROP_MAC0_ {
		FWP_BYTE_ARRAY6 localMacAddr;
		FWP_BYTE_ARRAY6 remoteMacAddr;
		UINT32          mediaType;
		UINT32          ifType;
		UINT16          etherType;
		UINT32          ndisPortNumber;
		UINT32          reserved;
		UINT16          vlanTag;
		UINT64          ifLuid;
		UINT64          filterId;
		UINT16          layerId;
		UINT32          reauthReason;
		UINT32          originalProfile;
		UINT32          currentProfile;
		UINT32          msFwpDirection;
		BOOL            isLoopback;
		FWP_BYTE_BLOB   vSwitchId;
		UINT32          vSwitchSourcePort;
		UINT32          vSwitchDestinationPort;
	  } FWPM_NET_EVENT_CLASSIFY_DROP_MAC0;
	*/
	/*DWORD FwpmEngineSetOption0(
		HANDLE             engineHandle,
		FWPM_ENGINE_OPTION option,
		const FWP_VALUE0   *newValue
	  );
	*/
	subLayer := gowindows.FwpmSublayer0{}
	subLayer.DisplayData.Name = windows.StringToUTF16Ptr(FIREWALL_SUBLAYER_NAMEW)
	subLayer.DisplayData.Description = windows.StringToUTF16Ptr(FIREWALL_SUBLAYER_NAMEW)
	subLayer.Flags = 0
	subLayer.Weight = 300

	err = gowindows.UuidCreate(&subLayer.SubLayerKey)
	if err != nil {
		return fmt.Errorf("UuidCreate ,%v", err)
	}

	err = gowindows.FwpmSubLayerAdd0(engineHandle, &subLayer, nil)
	if err != nil {
		return fmt.Errorf("FwpmSubLayerAdd0, %v\nMaybe administrator can?", err)
	}

	filter := gowindows.FwpmFilter0{}
	condition := make([]gowindows.FwpmFilterCondition0, 2)

	filter.SubLayerKey = subLayer.SubLayerKey
	filter.DisplayData.Name = windows.StringToUTF16Ptr(FIREWALL_SERVICE_NAMEW)
	filter.Weight.Type = gowindows.FWP_UINT8
	filter.Weight.SetUint8(0xF)
	filter.FilterCondition = &condition[0]
	filter.NumFilterConditions = uint32(len(condition))

	condition[0].FieldKey = gowindows.FWPM_CONDITION_IP_REMOTE_PORT
	condition[0].MatchType = gowindows.FWP_MATCH_EQUAL
	//FWP_MATCH_EQUAL Kiểm tra giá trị có bằng với điều kiện không
	condition[0].ConditionValue.Type = gowindows.FWP_UINT16
	// Chặn kết nối ra tới cổng 80
	condition[0].ConditionValue.SetUint16(80)

	condition[1].FieldKey = gowindows.FWPM_CONDITION_MAC_LOCAL_ADDRESS
	condition[1].MatchType = gowindows.FWP_MATCH_EQUAL
	condition[1].ConditionValue.Type = gowindows.FWP_BYTE_ARRAY6_TYPE
	//Chặn theo MAC....
	mac := "\x98\x54\x1B\x61\xB7\xCD"
	condition[1].ConditionValue.Data = uint(uintptr(unsafe.Pointer(C.CString(mac))))

	condition[2].FieldKey = gowindows.FWPM_CONDITION_IP_LOCAL_PORT
	condition[2].MatchType = gowindows.FWP_MATCH_EQUAL
	condition[2].ConditionValue.Type = gowindows.FWP_UINT16
	// Chặn kết nối tới cổng 22 ngăn kết nối ssh
	condition[2].ConditionValue.SetUint16(22)

	// Cho phép cả các yêu cầu IPv4
	filter.Action.Type = win.FWP_ACTION_PERMIT // FWP_ACTION_PERMIT
	filter.LayerKey = win.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	filter.Weight.Type = win.FWP_EMPTY
	filter.NumFilterConditions = 1

	var filterId gowindows.FilterId
	err = gowindows.FwpmFilterAdd0(engineHandle, &filter, nil, &filterId)
	if err != nil {
		return fmt.Errorf("ipv4-FwpmFilterAdd0, %v", err)
	}

	log.Println("Đang chặn kết nối ra ở cổng 80 trong 6s")
	time.Sleep(6 * time.Second)

	log.Println("Đang chặn kết nối ssh đến khi tắt trương trình")

	err = gowindows.FwpmFilterDeleteById0(engineHandle, filterId)
	if err != nil {
		return fmt.Errorf("FwpmFilterDeleteById0, %v", err)
	}

	log.Println("Đã mở lại kết nối ra ở cổng 80")

	time.Sleep(6 * time.Second)
	err = gowindows.FwpmEngineClose0(engineHandle)
	if err != nil {
		return err
	}
	return nil
}
