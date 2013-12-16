/*SDV_HARNESS_METAFILE=SDV_MP_PNP_HARNESS_SHUTDOWN.h*/
#include "sdv-model-common.h"
#ifdef Set_Harness
#if (SDV_MP_FLAG)
	#define SDV_HARNESS SDV_MP_PNP_HARNESS_SHUTDOWN
#else
	#pragma message("SDV_NA")
#endif
#endif
