/*SDV_HARNESS_METAFILE=SDV_PROT_PNP_HARNESS_BINDING.h*/
#include "sdv-model-common.h"
#ifdef Set_Harness
#if (SDV_PROT_FLAG)
	#define SDV_HARNESS SDV_PROT_PNP_HARNESS_BINDING
#else
	#pragma message("SDV_NA")
#endif
#endif
