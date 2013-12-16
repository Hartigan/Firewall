/*SDV_HARNESS_METAFILE=SDV_IFLAT_HARNESS.h*/
#include "sdv-model-common.h"
#ifdef Set_Harness
#if (SDV_MP_FLAG)
	#define SDV_HARNESS SDV_IFLAT_HARNESS  
#else
	#pragma message("SDV_NA")
#endif
#endif

