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
extern unsigned int summit_roam_delta;

extern unsigned int summit_scan_dwell;
extern unsigned int summit_scan_delay;
extern unsigned int summit_scan_passive_dwell;
extern unsigned int summit_scan_suspend_time;
extern unsigned int summit_dfs_disable;
#ifdef CONFIG_SDC_DMS
extern unsigned int summit_dms;
#endif

extern int summit_read_config(void);

#endif	// SDC_H
