#pragma once
#include <Windows.h>


#define MAX_PREFERRED_LENGTH    ((DWORD) -1)
#define NET_API_STATUS          DWORD
#define LG_INCLUDE_INDIRECT         (0x0001)
#define __TEXT(quote) L##quote      // r_winnt
#define TEXT(quote) __TEXT(quote)   // r_winnt
#define NET_API_FUNCTION    __stdcall
#define NERR_Success            0   
#define FILTER_NORMAL_ACCOUNT               (0x0002)
#define USER_PRIV_MASK      0x3
#define USER_PRIV_GUEST     0
#define USER_PRIV_USER      1
#define USER_PRIV_ADMIN     2
#define UF_SCRIPT                          0x0001
#define UF_ACCOUNTDISABLE                  0x0002
#define UF_HOMEDIR_REQUIRED                0x0008
#define UF_LOCKOUT                         0x0010
#define UF_PASSWD_NOTREQD                  0x0020
#define UF_PASSWD_CANT_CHANGE              0x0040
#define UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED 0x0080
#define POLICY_VIEW_LOCAL_INFORMATION              0x00000001L
#define POLICY_VIEW_AUDIT_INFORMATION              0x00000002L
#define POLICY_GET_PRIVATE_INFORMATION             0x00000004L
#define POLICY_TRUST_ADMIN                         0x00000008L
#define POLICY_CREATE_ACCOUNT                      0x00000010L
#define POLICY_CREATE_SECRET                       0x00000020L
#define POLICY_CREATE_PRIVILEGE                    0x00000040L
#define POLICY_SET_DEFAULT_QUOTA_LIMITS            0x00000080L
#define POLICY_SET_AUDIT_REQUIREMENTS              0x00000100L
#define POLICY_AUDIT_LOG_ADMIN                     0x00000200L
#define POLICY_SERVER_ADMIN                        0x00000400L
#define POLICY_LOOKUP_NAMES                        0x00000800L
#define POLICY_NOTIFICATION                        0x00001000L
#define POLICY_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED         |\
                               POLICY_VIEW_LOCAL_INFORMATION    |\
                               POLICY_VIEW_AUDIT_INFORMATION    |\
                               POLICY_GET_PRIVATE_INFORMATION   |\
                               POLICY_TRUST_ADMIN               |\
                               POLICY_CREATE_ACCOUNT            |\
                               POLICY_CREATE_SECRET             |\
                               POLICY_CREATE_PRIVILEGE          |\
                               POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                               POLICY_SET_AUDIT_REQUIREMENTS    |\
                               POLICY_AUDIT_LOG_ADMIN           |\
                               POLICY_SERVER_ADMIN              |\
                               POLICY_LOOKUP_NAMES)



typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is(Length / 2)]
#endif // MIDL_PASS
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef struct _LSA_OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PLSA_UNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;
typedef PVOID LSA_HANDLE, *PLSA_HANDLE;
typedef struct _USER_INFO_0 {
	LPWSTR   usri0_name;
}USER_INFO_0, *PUSER_INFO_0, *LPUSER_INFO_0;
typedef struct _LOCALGROUP_USERS_INFO_0 {
	LPWSTR  lgrui0_name;
} LOCALGROUP_USERS_INFO_0, *PLOCALGROUP_USERS_INFO_0, *LPLOCALGROUP_USERS_INFO_0;
typedef struct _USER_INFO_23 {
	LPWSTR   usri23_name;
	LPWSTR   usri23_full_name;
	LPWSTR   usri23_comment;
	DWORD    usri23_flags;
	PSID     usri23_user_sid;
}USER_INFO_23, *PUSER_INFO_23, *LPUSER_INFO_23;
typedef struct _USER_INFO_1 {
	LPWSTR   usri1_name;
	LPWSTR   usri1_password;
	DWORD    usri1_password_age;
	DWORD    usri1_priv;
	LPWSTR   usri1_home_dir;
	LPWSTR   usri1_comment;
	DWORD    usri1_flags;
	LPWSTR   usri1_script_path;
}USER_INFO_1, *PUSER_INFO_1, *LPUSER_INFO_1;
typedef struct _LOCALGROUP_INFO_0 {
	LPWSTR   lgrpi0_name;
}LOCALGROUP_INFO_0, *PLOCALGROUP_INFO_0, *LPLOCALGROUP_INFO_0;
typedef struct _GROUP_INFO_0 {
	LPWSTR   grpi0_name;
}GROUP_INFO_0, *PGROUP_INFO_0, *LPGROUP_INFO_0;
typedef struct _LOCALGROUP_MEMBERS_INFO_3 {
	LPWSTR       lgrmi3_domainandname;
} LOCALGROUP_MEMBERS_INFO_3, *PLOCALGROUP_MEMBERS_INFO_3,
*LPLOCALGROUP_MEMBERS_INFO_3;
typedef struct _USER_INFO_3 {
	LPWSTR   usri3_name;
	LPWSTR   usri3_password;
	DWORD    usri3_password_age;
	DWORD    usri3_priv;
	LPWSTR   usri3_home_dir;
	LPWSTR   usri3_comment;
	DWORD    usri3_flags;
	LPWSTR   usri3_script_path;
	DWORD    usri3_auth_flags;
	LPWSTR   usri3_full_name;
	LPWSTR   usri3_usr_comment;
	LPWSTR   usri3_parms;
	LPWSTR   usri3_workstations;
	DWORD    usri3_last_logon;
	DWORD    usri3_last_logoff;
	DWORD    usri3_acct_expires;
	DWORD    usri3_max_storage;
	DWORD    usri3_units_per_week;
	PBYTE    usri3_logon_hours;
	DWORD    usri3_bad_pw_count;
	DWORD    usri3_num_logons;
	LPWSTR   usri3_logon_server;
	DWORD    usri3_country_code;
	DWORD    usri3_code_page;
	DWORD    usri3_user_id;
	DWORD    usri3_primary_group_id;
	LPWSTR   usri3_profile;
	LPWSTR   usri3_home_dir_drive;
	DWORD    usri3_password_expired;
}USER_INFO_3, *PUSER_INFO_3, *LPUSER_INFO_3;

typedef struct _USER_INFO_4 {
	LPWSTR   usri4_name;
	LPWSTR   usri4_password;
	DWORD    usri4_password_age;
	DWORD    usri4_priv;
	LPWSTR   usri4_home_dir;
	LPWSTR   usri4_comment;
	DWORD    usri4_flags;
	LPWSTR   usri4_script_path;
	DWORD    usri4_auth_flags;
	LPWSTR   usri4_full_name;
	LPWSTR   usri4_usr_comment;
	LPWSTR   usri4_parms;
	LPWSTR   usri4_workstations;
	DWORD    usri4_last_logon;
	DWORD    usri4_last_logoff;
	DWORD    usri4_acct_expires;
	DWORD    usri4_max_storage;
	DWORD    usri4_units_per_week;
	PBYTE    usri4_logon_hours;
	DWORD    usri4_bad_pw_count;
	DWORD    usri4_num_logons;
	LPWSTR   usri4_logon_server;
	DWORD    usri4_country_code;
	DWORD    usri4_code_page;
	PSID     usri4_user_sid;
	DWORD    usri4_primary_group_id;
	LPWSTR   usri4_profile;
	LPWSTR   usri4_home_dir_drive;
	DWORD    usri4_password_expired;
}USER_INFO_4, *PUSER_INFO_4, *LPUSER_INFO_4;