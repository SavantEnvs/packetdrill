/* Leak detection off for every ASan target (SPEC §6.2 item 15); ASan and UBSan stay active.
 * packetdrill's parser deliberately never frees the parsed script before exit. */
int __lsan_is_turned_off(void) { return 1; }
