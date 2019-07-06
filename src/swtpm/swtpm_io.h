/********************************************************************************/
/*                                                                              */
/*                              TPM Host IO                                     */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_io.h 4211 2010-11-22 21:07:24Z kgoldman $                */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef _SWTPM_IO_H_
#define _SWTPM_IO_H_

typedef struct TPM_CONNECTION_FD {
    int fd;     /* for socket, just an int */
} TPM_CONNECTION_FD;

TPM_RESULT SWTPM_IO_Init(void);
TPM_RESULT SWTPM_IO_Connect(TPM_CONNECTION_FD *connection_fd,
                            int notify_fd);
TPM_RESULT SWTPM_IO_Read(TPM_CONNECTION_FD *connection_fd,
                         unsigned char *buffer,
                         uint32_t *paramSize,
                         size_t buffer_size);
TPM_RESULT SWTPM_IO_Write(TPM_CONNECTION_FD *connection_fd,
                          const struct iovec *iovec,
                          int iovcnt);
TPM_RESULT SWTPM_IO_Disconnect(TPM_CONNECTION_FD *connection_fd);
TPM_RESULT SWTPM_IO_SetSocketFD(int fd);
int SWTPM_IO_GetSocketFD(void);

#define LOAD32(buffer,offset)         ( ntohl(*(uint32_t *)&(buffer)[(offset)]) )
#define LOAD16(buffer,offset)         ( ntohs(*(uint16_t *)&(buffer)[(offset)]) )
#define LOAD8(buffer,offset)          (      (*(uint8_t  *)&(buffer)[(offset)]) )

#endif /* _SWTPM_IO_H_ */

