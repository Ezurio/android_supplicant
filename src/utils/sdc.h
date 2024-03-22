/*
 * wpa_supplicant - Summit extensions
 * Copyright (c) 2010 -- Summit Data Communications
 *
 * This software may be distributed under the terms of BSD license.
 *
 * See README and COPYING for more details.
 */

#ifndef SDC_H
#define SDC_H

extern unsigned int sdc_eap_timeout;
extern unsigned int laird_roam_delta;
extern unsigned int laird_scan_dwell;
extern unsigned int laird_scan_delay;
extern unsigned int laird_scan_passive_dwell;
extern unsigned int laird_scan_suspend_time;
extern unsigned int laird_dfs_disable;

extern int laird_read_config(void);

#ifdef CONFIG_SDC_DMS
extern unsigned int laird_dms;
#endif

#endif	// SDC_H
