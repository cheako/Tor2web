/*
 * util.c
 *
 *  Created on: Oct 11, 2017
 *      Author: cheako
 */

/******************************************************************************

 Online C Compiler.
 Code, Compile, Run and Debug C program online.
 Write your code in this editor and press "Run" button to compile and execute it.

 *******************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

void
show (const char *proc, const char *host, int ret, struct addrinfo *addr)
{
  printf ("%s: %s: %d: %d", proc, host, ret, addr->ai_family);
}

void
try (const char *i)
{
  int ret;
  struct addrinfo *res;
  struct addrinfo a =
    { .ai_family = AF_UNSPEC, .ai_protocol = SOCK_STREAM, .ai_addrlen = sizeof(struct addrinfo_storage) };

  ret = getaddrinfo (i, "80", &a, &res);

}

int
main ()
{
  try ("::");
  try ("127.0.0.1");
  try ("/pie/try");
  try ("try/pie");
  try ("HelloWorld.socket");
  try ("Hello World");
  return 0;
}
