#ifndef macros_h
#define macros_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static inline bool isValidNibble(uint8_t nibble){return nibble<16;}

#define CheckNB(n) \
  if(!isValidNibble(n)){perror("Error extracting nibble");exit(errno);}

#define SYSC(val, cmd, msg) \
  if((val=cmd)==-1){perror(msg);exit(errno);}

#define SYS(cmd,msg) \
  if( cmd == -1){perror(msg);exit(errno);}

#define SYSCN(val, cmd, msg) \
  if((val=cmd)==NULL){perror(msg);exit(errno);}

#define SYSC0(val,cmd,msg) \
  if(!(val=cmd)){perror(msg);exit(errno);}

#define SUCC0(cmd,msg) \
  if(cmd!=0){perror(msg);exit(errno);}

#endif
