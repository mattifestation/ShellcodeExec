#include <windows.h>
#include <stdio.h>
#include <tchar.h>

// The shellcode will be treated as a function with no arguments and no return value.
typedef VOID (*SHELLCODE)();

INT _tmain( INT argc, TCHAR *argv[] )
{
	HANDLE hFile;
	BOOL bDebugBreak = FALSE;
	DWORD dwFileSize;
	DWORD dwBytesRead;
	BOOL bReadSuccess;
	PBYTE lpShellcode;
	SHELLCODE execShellcode;
	const PTCHAR syntaxMessage = TEXT("Executes shellcode from a file.\n\n%s shellcodeBinFile [/CC]\n\n  /CC          Prepends a debug breakpoint (INT3) to the shellcode.\n");

	if ((argc < 2) || (argc > 3))
	{
		goto error_args;
	}

	if ( argc == 3 )
	{
		if ( _tcsicmp( argv[2], TEXT("/CC") ) == 0 )
		{
			bDebugBreak = TRUE;
		}
		else
		{
			goto error_args;
		}
	}

	_tprintf( TEXT("\n") );

	hFile = CreateFile(	argv[1],
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL );

	if ( hFile == INVALID_HANDLE_VALUE ) 
    { 
        _tprintf( TEXT("Error: Unable to open file.\n"), argv[1] );
        return 1;
    }

	dwFileSize = GetFileSize( hFile, NULL );

	if ( dwFileSize == INVALID_FILE_SIZE )
	{
		_tprintf( TEXT("Error: Invalid file size.\n") );
		goto error_fail; 
	}

	lpShellcode = (PBYTE) VirtualAlloc( 0,
									    dwFileSize + 1,
									    MEM_COMMIT,
									    PAGE_EXECUTE_READWRITE );

	if ( lpShellcode == NULL )
	{
		_tprintf( TEXT("Error: Unable to allocate RWX memory. (0x%08x)\n"), GetLastError() );
		goto error_fail;
	}

	if ( bDebugBreak )
	{
		*lpShellcode = 0xCC;
		bReadSuccess = ReadFile( hFile, (lpShellcode + 1), dwFileSize, &dwBytesRead, NULL );
	}
	else
	{
		bReadSuccess = ReadFile( hFile, lpShellcode, dwFileSize, &dwBytesRead, NULL );
	}

	if ( !bReadSuccess )
	{
		_tprintf( TEXT("Error: Unable to read file. (0x%08x)\n"), GetLastError() );
		goto error_fail;
	}

	if ( dwBytesRead == 0 )
	{
		_tprintf( TEXT("Error: No bytes were read.\n") );
		goto error_fail;
	}

	CloseHandle( hFile );

	#pragma warning( disable : 4055 )
	execShellcode = (SHELLCODE) lpShellcode;
	#pragma warning( default : 4055 )

	_tprintf( TEXT("Executing shellcode...\n") );

	execShellcode();

	_tprintf( TEXT("Shellcode execution complete!\n") );

	return 0;

error_fail:
	CloseHandle(hFile);
	return 1;

error_args:
	_tprintf(syntaxMessage, argv[0]);
	return 1;
}