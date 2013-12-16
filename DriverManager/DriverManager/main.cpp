#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <windows.h>
#include "structures.h"

//errors
#define HANDLE_ERROR 1;
#define QUERY_ERROR 2;

//menu values
#define MENU_VIEW_RULES 1
#define MENU_ADD_IPV4 2
#define MENU_ADD_IPV6 3
#define MENU_REM_IPV4 4
#define MENU_REM_IPV6 5
#define MENU_ACTIVATE 6
#define MENU_DEACTIVATE 7
#define MENU_EXIT 8

using namespace std;

//global variables
PRULE_IPV4 IPv4List = NULL;
PRULE_IPV6 IPv6List = NULL;

//functions defenition
//driver functions
LONG AddIPv4Rule(PRULE_IPV4 Rule);
LONG DelIPv4Rule(ULONG Id);
LONG AddIPv6Rule(PRULE_IPV6 Rule);
LONG DelIPv6Rule(ULONG Id);
LONG Activate();
LONG Deactivate();
HANDLE GetDriverHandle();
//gui functions
VOID PrintIPv4Rule(PRULE_IPV4 Rule);
VOID PrintIPv6Rule(PRULE_IPV6 Rule);
VOID PrintListRules();
VOID PrintMenu();
VOID MenuSelector(int selector);
VOID AddIPv4Rule();
VOID AddIPv6Rule();
VOID RemoveIPv4Rule();
VOID RemoveIPv6Rule();
VOID ActivateFirewall();
VOID DeactivateFirewall();
VOID LoadState();
VOID SaveState();
ULONG NewId();
VOID DisposeGlobals();

int main()
{
	LoadState();
	while (true)
	{
		system("cls");
		PrintMenu();
		CHAR ch;
		scanf("%d", &ch);
		MenuSelector(ch);
		printf("\n");
		system("pause");
	}
	return 0;
}

LONG AddIPv4Rule(PRULE_IPV4 Rule)
{
	HANDLE hHandle = GetDriverHandle();
	if (!hHandle)
	{
		return HANDLE_ERROR;
	}

	void *buffer = malloc(sizeof(RULE_IPV4));
	memcpy(buffer, Rule, sizeof(RULE_IPV4));

	LONG Result = 0;
	DWORD dwReturnBytes, ioctl = IOCTL_ADD_IPV4_RULE;
	if (DeviceIoControl(hHandle, ioctl,
		buffer, sizeof(RULE_IPV4),//in
		buffer, sizeof(RULE_IPV4),//out
		&dwReturnBytes, NULL))
	{
		cout << "ok" << endl;
	}
	else
	{
		cout << "very bad" << endl;
		Result = QUERY_ERROR;
	}
	free(buffer);
	CloseHandle(hHandle);
	return Result;
}

LONG DelIPv4Rule(ULONG Id)
{
	HANDLE hHandle = GetDriverHandle();
	if (!hHandle)
	{
		return HANDLE_ERROR;
	}

	void *buffer = malloc(sizeof(ULONG));
	memcpy(buffer, &Id, sizeof(ULONG));

	LONG Result = 0;
	DWORD dwReturnBytes, ioctl = IOCTL_DEL_IPV4_RULE;
	if (DeviceIoControl(hHandle, ioctl,
		buffer, sizeof(ULONG),//in
		buffer, sizeof(ULONG),//out
		&dwReturnBytes, NULL))
	{
		cout << "ok" << endl;
	}
	else
	{
		cout << "fail" << endl;
		Result = QUERY_ERROR;
	}
	free(buffer);
	CloseHandle(hHandle);
	return Result;
}

LONG AddIPv6Rule(PRULE_IPV6 Rule)
{
	HANDLE hHandle = GetDriverHandle();
	if (!hHandle)
	{
		return HANDLE_ERROR;
	}

	void *buffer = malloc(sizeof(RULE_IPV6));
	memcpy(buffer, Rule, sizeof(RULE_IPV6));

	LONG Result = 0;
	DWORD dwReturnBytes, ioctl = IOCTL_ADD_IPV6_RULE;
	if (DeviceIoControl(hHandle, ioctl,
		buffer, sizeof(RULE_IPV6),//in
		buffer, sizeof(RULE_IPV6),//out
		&dwReturnBytes, NULL))
	{
		cout << "ok" << endl;
	}
	else
	{
		cout << "fail" << endl;
		Result = QUERY_ERROR;
	}
	free(buffer);
	CloseHandle(hHandle);
	return Result;
}

LONG DelIPv6Rule(ULONG Id)
{
	HANDLE hHandle = GetDriverHandle();
	if (!hHandle)
	{
		return HANDLE_ERROR;
	}

	void *buffer = malloc(sizeof(ULONG));
	memcpy(buffer, &Id, sizeof(ULONG));

	LONG Result = 0;
	DWORD dwReturnBytes, ioctl = IOCTL_DEL_IPV6_RULE;
	if (DeviceIoControl(hHandle, ioctl,
		buffer, sizeof(ULONG),//in
		buffer, sizeof(ULONG),//out
		&dwReturnBytes, NULL))
	{
		cout << "ok" << endl;
	}
	else
	{
		cout << "fail" << endl;
		Result = QUERY_ERROR;
	}
	free(buffer);
	CloseHandle(hHandle);
	return Result;
}

LONG Activate()
{
	HANDLE hHandle = GetDriverHandle();
	if (!hHandle)
	{
		return HANDLE_ERROR;
	}

	LONG Result = 0;
	DWORD dwReturnBytes, ioctl = IOCTL_ACTIVATE_FILTER;
	if (DeviceIoControl(hHandle, ioctl,
		0, 0,//in
		0, 0,//out
		&dwReturnBytes, NULL))
	{
		cout << "ok" << endl;
	}
	else
	{
		cout << "fail" << endl;
		Result = QUERY_ERROR;
	}

	CloseHandle(hHandle);
	return Result;
}

LONG Deactivate()
{
	HANDLE hHandle = GetDriverHandle();
	if (!hHandle)
	{
		return HANDLE_ERROR;
	}

	LONG Result = 0;
	DWORD dwReturnBytes, ioctl = IOCTL_DEACTIVATE_FILTER;
	if (DeviceIoControl(hHandle, ioctl,
		0, 0,//in
		0, 0,//out
		&dwReturnBytes, NULL))
	{
		cout << "ok" << endl;
	}
	else
	{
		cout << "fail" << endl;
		Result = QUERY_ERROR;
	}

	CloseHandle(hHandle);
	return Result;
}

HANDLE GetDriverHandle()
{
	HANDLE hHandle =
		CreateFile("\\\\.\\NDISFilterDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hHandle == INVALID_HANDLE_VALUE)
	{
		printf("ERR: can not access driver\n");
		return NULL;
	}

	return hHandle;
}

VOID PrintIPv6Rule(PRULE_IPV6 Rule)
{
	printf("Id: %lu Range: %x:%x:%x:%x:%x:%x:%x:%x-%x:%x:%x:%x:%x:%x:%x:%x\n",
		Rule->Id,
		Rule->Begin[0],
		Rule->Begin[1],
		Rule->Begin[2],
		Rule->Begin[3],
		Rule->Begin[4],
		Rule->Begin[5],
		Rule->Begin[6],
		Rule->Begin[7],
		Rule->Begin[8],
		Rule->Begin[9],
		Rule->Begin[10],
		Rule->Begin[11],
		Rule->Begin[12],
		Rule->Begin[13],
		Rule->Begin[14],
		Rule->Begin[15],
		Rule->End[0],
		Rule->End[1],
		Rule->End[2],
		Rule->End[3],
		Rule->End[4],
		Rule->End[5],
		Rule->End[6],
		Rule->End[7],
		Rule->End[8],
		Rule->End[9],
		Rule->End[10],
		Rule->End[11],
		Rule->End[12],
		Rule->End[13],
		Rule->End[14],
		Rule->End[15]);
}

VOID PrintIPv4Rule(PRULE_IPV4 Rule)
{
	printf("Id: %lu Range: %d.%d.%d.%d-%d.%d.%d.%d\n",
		Rule->Id,
		Rule->Begin[0],
		Rule->Begin[1], 
		Rule->Begin[2], 
		Rule->Begin[3],
		Rule->End[0],
		Rule->End[1], 
		Rule->End[2], 
		Rule->End[3]);
}

VOID PrintListRules()
{
	PRULE_IPV4 CurrentRuleIPv4 = IPv4List;
	printf("IPv4 Rules:\n");
	while (CurrentRuleIPv4 != NULL)
	{
		PrintIPv4Rule(CurrentRuleIPv4);
		CurrentRuleIPv4 = (PRULE_IPV4)CurrentRuleIPv4->Next;
	}

	PRULE_IPV6 CurrentRuleIPv6 = IPv6List;
	printf("IPv6 Rules:\n");
	while (CurrentRuleIPv4 != NULL)
	{
		PrintIPv6Rule(CurrentRuleIPv6);
		CurrentRuleIPv6 = (PRULE_IPV6)CurrentRuleIPv6->Next;
	}
}

VOID PrintMenu()
{
	printf("1.View rules\n");
	printf("2.Add IPv4 rule\n");
	printf("3.Add IPv6 rule\n");
	printf("4.Remove IPv4 rule\n");
	printf("5.Remove IPv6 rule\n");
	printf("6.Activate filter\n");
	printf("7.Deactivate filter\n");
	printf("8.Exit\n");
	printf("Enter command(1-8):");
}

VOID MenuSelector(int selector)
{
	switch (selector)
	{
	case MENU_VIEW_RULES:
		PrintListRules();
		break;
	case MENU_ADD_IPV4:
		AddIPv4Rule();
		break;
	case MENU_ADD_IPV6:
		AddIPv6Rule();
		break;
	case MENU_REM_IPV4:
		RemoveIPv4Rule();
		break;
	case MENU_REM_IPV6:
		RemoveIPv6Rule();
		break;
	case MENU_ACTIVATE:
		ActivateFirewall();
		break;
	case MENU_DEACTIVATE:
		DeactivateFirewall();
		break;
	case MENU_EXIT:
		SaveState();
		exit(0);
		break;
	default:
		printf("Invalid character\n");
	}
}

VOID AddIPv4Rule()
{
	printf("Enter IPv4 range(example 0.0.0.0-255.255.255.255):");
	PRULE_IPV4 rule = (PRULE_IPV4)malloc(sizeof(RULE_IPV4));
	scanf("%d.%d.%d.%d-%d.%d.%d.%d",
		&rule->Begin[0],
		&rule->Begin[1],
		&rule->Begin[2],
		&rule->Begin[3],
		&rule->End[0],
		&rule->End[1],
		&rule->End[2],
		&rule->End[3]);
	rule->Id = NewId();
	if (!AddIPv4Rule(rule))
	{
		rule->Next = IPv4List;
		IPv4List = rule;
		printf("Complete\n");
	}
	else
	{
		free(rule);
	}
	printf("\n");
}

VOID AddIPv6Rule()
{
	printf("Enter IPv6 range(example 0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0-ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff):");
	PRULE_IPV6 rule = (PRULE_IPV6)malloc(sizeof(RULE_IPV6));
	scanf("%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x-%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
		&rule->Begin[0],
		&rule->Begin[1],
		&rule->Begin[2],
		&rule->Begin[3],
		&rule->Begin[4],
		&rule->Begin[5],
		&rule->Begin[6],
		&rule->Begin[7],
		&rule->Begin[8],
		&rule->Begin[9],
		&rule->Begin[10],
		&rule->Begin[11],
		&rule->Begin[12],
		&rule->Begin[13],
		&rule->Begin[14],
		&rule->Begin[15],
		&rule->End[0],
		&rule->End[1],
		&rule->End[2],
		&rule->End[3],
		&rule->End[4],
		&rule->End[5],
		&rule->End[6],
		&rule->End[7],
		&rule->End[8],
		&rule->End[9],
		&rule->End[10],
		&rule->End[11],
		&rule->End[12],
		&rule->End[13],
		&rule->End[14],
		&rule->End[15]);
	rule->Id = NewId();
	if (!AddIPv6Rule(rule))
	{
		rule->Next = IPv6List;
		IPv6List = rule;
		printf("Complete\n");
	}
	else
	{
		free(rule);
	}
	printf("\n");
}

VOID RemoveIPv4Rule()
{
	printf("Enter IPv4 rule id(example 1):");
	ULONG id;
	scanf("%lu",&id);
	if (!DelIPv4Rule(id))
	{
		PRULE_IPV4 CurrentRule = IPv4List;
		if (CurrentRule->Id == id)
		{
			IPv4List = (PRULE_IPV4)CurrentRule->Next;
			free(CurrentRule);
		}
		else
		{
			PRULE_IPV4 PrevRule = NULL;
			while (CurrentRule != NULL)
			{
				if (CurrentRule->Id == id)
				{
					PrevRule->Next = CurrentRule->Next;
					free(CurrentRule);
					break;
				}
				PrevRule = CurrentRule;
				CurrentRule = (PRULE_IPV4)CurrentRule->Next;
			}
		}
		printf("Complete\n");
	}
	printf("\n");
}

VOID RemoveIPv6Rule()
{
	printf("Enter IPv6 rule id(example 1):");
	ULONG id;
	scanf("%lu",&id);
	if (!DelIPv6Rule(id))
	{
		PRULE_IPV6 CurrentRule = IPv6List;
		if (CurrentRule->Id == id)
		{
			IPv6List = (PRULE_IPV6)CurrentRule->Next;
			free(CurrentRule);
		}
		else
		{
			PRULE_IPV6 PrevRule = NULL;
			while (CurrentRule != NULL)
			{
				if (CurrentRule->Id == id)
				{
					PrevRule->Next = CurrentRule->Next;
					free(CurrentRule);
					break;
				}
				PrevRule = CurrentRule;
				CurrentRule = (PRULE_IPV6)CurrentRule->Next;
			}
		}
		printf("Complete\n");
	}
	printf("\n");
}

VOID ActivateFirewall()
{
	if (!Activate())
	{
		printf("Filter is active\n");
	}
	printf("\n");
}

VOID DeactivateFirewall()
{
	if (!Deactivate())
	{
		printf("Filter isn't active\n");
	}
	printf("\n");
}

VOID LoadState()
{
	ifstream file;
	CHAR Buffer[256];
	file.open("Rules.dat", std::ios::in);
	INT RulesCount;

	RulesCount= 0;
	file >> RulesCount;
	IPv4List = NULL;
	for (int i = 0; i < RulesCount; i++)
	{
		PRULE_IPV4 rule = (PRULE_IPV4)malloc(sizeof(RULE_IPV4));
		file >> Buffer;
		sscanf(Buffer, "%lu|%d.%d.%d.%d-%d.%d.%d.%d",
			&rule->Id,
			&rule->Begin[0],
			&rule->Begin[1],
			&rule->Begin[2],
			&rule->Begin[3],
			&rule->End[0],
			&rule->End[1],
			&rule->End[2],
			&rule->End[3]);
		rule->Next = IPv4List;
		IPv4List = rule;
		DelIPv4Rule(rule->Id);
		AddIPv4Rule(rule);
	}

	RulesCount = 0;
	file >> RulesCount;
	IPv6List = NULL;
	for (int i = 0; i < RulesCount; i++)
	{
		PRULE_IPV6 rule = (PRULE_IPV6)malloc(sizeof(RULE_IPV6));
		file >> Buffer;
		sscanf(Buffer, "%lu|%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x-%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
			&rule->Id,
			&rule->Begin[0],
			&rule->Begin[1],
			&rule->Begin[2],
			&rule->Begin[3],
			&rule->Begin[4],
			&rule->Begin[5],
			&rule->Begin[6],
			&rule->Begin[7],
			&rule->Begin[8],
			&rule->Begin[9],
			&rule->Begin[10],
			&rule->Begin[11],
			&rule->Begin[12],
			&rule->Begin[13],
			&rule->Begin[14],
			&rule->Begin[15],
			&rule->End[0],
			&rule->End[1],
			&rule->End[2],
			&rule->End[3],
			&rule->End[4],
			&rule->End[5],
			&rule->End[6],
			&rule->End[7],
			&rule->End[8],
			&rule->End[9],
			&rule->End[10],
			&rule->End[11],
			&rule->End[12],
			&rule->End[13],
			&rule->End[14],
			&rule->End[15]);
		rule->Next = IPv6List;
		IPv6List = rule;
		DelIPv6Rule(rule->Id);
		AddIPv6Rule(rule);
	}
}

VOID SaveState()
{
	ofstream file;
	CHAR Buffer[256];
	file.open("Rules.dat", std::ios::out);
	INT RulesCount;

	RulesCount = 0;
	PRULE_IPV4 CurrentRuleIPv4 = IPv4List;
	while (CurrentRuleIPv4 != NULL)
	{
		RulesCount++;
		CurrentRuleIPv4 = (PRULE_IPV4)CurrentRuleIPv4->Next;
	}
	file << RulesCount << endl;

	CurrentRuleIPv4 = IPv4List;
	while (CurrentRuleIPv4 != NULL)
	{
		sprintf(Buffer, "%lu|%d.%d.%d.%d-%d.%d.%d.%d",
			CurrentRuleIPv4->Id,
			CurrentRuleIPv4->Begin[0],
			CurrentRuleIPv4->Begin[1],
			CurrentRuleIPv4->Begin[2],
			CurrentRuleIPv4->Begin[3],
			CurrentRuleIPv4->End[0],
			CurrentRuleIPv4->End[1],
			CurrentRuleIPv4->End[2],
			CurrentRuleIPv4->End[3]);
		file << Buffer << endl;
		CurrentRuleIPv4 = (PRULE_IPV4)CurrentRuleIPv4->Next;
	}

	RulesCount = 0;
	PRULE_IPV6 CurrentRuleIPv6 = IPv6List;
	while (CurrentRuleIPv6 != NULL)
	{
		RulesCount++;
		CurrentRuleIPv6 = (PRULE_IPV6)CurrentRuleIPv6->Next;
	}
	file << RulesCount << endl;

	CurrentRuleIPv6 = IPv6List;
	while (CurrentRuleIPv6 != NULL)
	{
		sprintf(Buffer, "%lu|%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x-%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
			&CurrentRuleIPv6->Id,
			&CurrentRuleIPv6->Begin[0],
			&CurrentRuleIPv6->Begin[1],
			&CurrentRuleIPv6->Begin[2],
			&CurrentRuleIPv6->Begin[3],
			&CurrentRuleIPv6->Begin[4],
			&CurrentRuleIPv6->Begin[5],
			&CurrentRuleIPv6->Begin[6],
			&CurrentRuleIPv6->Begin[7],
			&CurrentRuleIPv6->Begin[8],
			&CurrentRuleIPv6->Begin[9],
			&CurrentRuleIPv6->Begin[10],
			&CurrentRuleIPv6->Begin[11],
			&CurrentRuleIPv6->Begin[12],
			&CurrentRuleIPv6->Begin[13],
			&CurrentRuleIPv6->Begin[14],
			&CurrentRuleIPv6->Begin[15],
			&CurrentRuleIPv6->End[0],
			&CurrentRuleIPv6->End[1],
			&CurrentRuleIPv6->End[2],
			&CurrentRuleIPv6->End[3],
			&CurrentRuleIPv6->End[4],
			&CurrentRuleIPv6->End[5],
			&CurrentRuleIPv6->End[6],
			&CurrentRuleIPv6->End[7],
			&CurrentRuleIPv6->End[8],
			&CurrentRuleIPv6->End[9],
			&CurrentRuleIPv6->End[10],
			&CurrentRuleIPv6->End[11],
			&CurrentRuleIPv6->End[12],
			&CurrentRuleIPv6->End[13],
			&CurrentRuleIPv6->End[14],
			&CurrentRuleIPv6->End[15]);
		file << Buffer << endl;
		CurrentRuleIPv6 = (PRULE_IPV6)CurrentRuleIPv6->Next;
	}
}

VOID DisposeGlobals()
{
	PRULE_IPV4 CurrentRuleIPv4 = IPv4List;
	while (CurrentRuleIPv4 != NULL)
	{
		PRULE_IPV4 tmp = (PRULE_IPV4)CurrentRuleIPv4->Next;
		free(CurrentRuleIPv4);
		CurrentRuleIPv4 = tmp;
	}

	PRULE_IPV6 CurrentRuleIPv6 = IPv6List;
	while (CurrentRuleIPv6 != NULL)
	{
		PRULE_IPV6 tmp = (PRULE_IPV6)CurrentRuleIPv6->Next;
		free(CurrentRuleIPv6);
		CurrentRuleIPv6 = tmp;
	}
}

ULONG NewId()
{
	ULONG Id = 0;
	PRULE_IPV4 CurrentRuleIPv4 = IPv4List;
	while (CurrentRuleIPv4 != NULL)
	{
		if (CurrentRuleIPv4->Id >= Id)
		{
			Id = CurrentRuleIPv4->Id + 1;
		}
		CurrentRuleIPv4 = (PRULE_IPV4)CurrentRuleIPv4->Next;
	}

	PRULE_IPV6 CurrentRuleIPv6 = IPv6List;
	while (CurrentRuleIPv6 != NULL)
	{
		if (CurrentRuleIPv6->Id >= Id)
		{
			Id = CurrentRuleIPv6->Id + 1;
		}
		CurrentRuleIPv6 = (PRULE_IPV6)CurrentRuleIPv6->Next;
	}

	return Id;
}

