/* SDV_DIRQL:

   The OS model raises IRQL to DIRQL by the use of the SDV_DIRQL
   macro.  DIRQL is not a specific IRQL, but rather a range of
   possible Device IRQLs (On X86 from 3-26, on AMD64 from 3-11 and on
   IA64 from 4-11).  The OS Model nevertheless declares SDV_DIRQL as
   the concrete value 4 (which is a valid DIRQL representative for all
   architectures).  See ntddk_slic.h for details why this
   concretization is proper and will not result in loss of any traces.
*/
#define SDV_DIRQL 4
#define SDV_IRQL_PREVIOUS_EQUAL(irql) (irql == sdv_irql_previous)
#define STATUS_DELETE_PENDING 3221225558

