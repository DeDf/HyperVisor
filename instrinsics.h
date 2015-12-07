
#ifndef __INSTRINSICS_H__
#define __INSTRINSICS_H__

 ULONG_PTR __rol(ULONG_PTR val, UCHAR rotation);
 ULONG_PTR __ror(ULONG_PTR val, UCHAR rotation);

 void __cli();
 void __sti();

 ULONG_PTR __sgdt(__out void * gdtr);
 ULONG_PTR __vmx_call(__in ULONG_PTR);

 ULONG_PTR __readcs();
 ULONG_PTR __readds();
 ULONG_PTR __reades();
 ULONG_PTR __readss();
 ULONG_PTR __readfs();
 ULONG_PTR __readgs();
 ULONG_PTR __sldt();
 ULONG_PTR __str();

 ULONG_PTR __xchgds(__inout ULONG_PTR* ds);
 ULONG_PTR __writeds(__in ULONG_PTR ds);

#endif //__INSTRINSICS_H__
