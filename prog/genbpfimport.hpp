#ifdef __cplusplus
extern "C" {
#endif
int GenBPFProg(char *bpfProgAttr, char *bpfMapAttr, int MaxMapAttrSize);
int insnSize;
int licenseSize;
int funcInfoSize;
int lineInfoSize;
int bpfAttrSize();
#ifdef __cplusplus
}
#endif
