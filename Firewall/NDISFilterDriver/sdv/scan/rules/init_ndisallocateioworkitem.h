/*SDV_HARNESS_METAFILE=SDV_PNP_HARNESS_INIT.h*/
#include "sdv-model-common.h"
#ifdef Set_Harness
#if (SDV_MP_FLAG)
	#define SDV_HARNESS SDV_MP_PNP_HARNESS_INIT  
#else
	#pragma message("SDV_NA")
#endif
#endif
