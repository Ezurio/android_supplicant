#include "includes.h"
#include "common.h"
#include "common/defs.h"
#include "utils/sdc.h"

#if defined(_SDC_)

unsigned int sdc_eap_timeout = 10;
unsigned int summit_roam_delta;
unsigned int summit_scan_dwell;
unsigned int summit_scan_delay;
unsigned int summit_scan_passive_dwell;
unsigned int summit_scan_suspend_time;
unsigned int summit_dfs_disable;
#ifdef CONFIG_SDC_DMS
unsigned int summit_dms;
#endif

typedef struct {
	const char *key;
	unsigned int *pval;
	unsigned int def;
	unsigned int min;
	unsigned int max;
	unsigned int allow_zero;
} sSummitGlobal;

static sSummitGlobal lg[] = {
	{ "EAPTIMEOUT", &sdc_eap_timeout, 10, 3, 60, 0 },
	{ "ROAMDELTA", &summit_roam_delta, 0, 0, 10, 1 },
	{ "SCANDWELLTIME", &summit_scan_dwell, 0, 10, 250, 1 },
	{ "SCANDELAYTIME", &summit_scan_delay, 0, 10, 250, 1 },
	{ "SCANPASSIVEDWELLTIME", &summit_scan_passive_dwell, 0, 10, 250, 1 },
	{ "SCANSUSPENDTIME", &summit_scan_suspend_time, 0, 10, 250, 1 },
	{ "DFSDISABLE", &summit_dfs_disable, 0, 0, 1, 1 },
#ifdef CONFIG_SDC_DMS
	{ "DMS", &summit_dms, 0, 0, 6, 1 },
#endif
	{ NULL, NULL, 0, 0, 0, 0 }
};

static void summit_init_globals(void)
{
	sSummitGlobal *plg;
	for (plg=lg; plg->key; plg++) {
		*(plg->pval) = plg->def;
	}
}

static int summit_int_globals(const char *line)
{
	sSummitGlobal *plg;
	for (plg=lg; plg->key; plg++) {
		int len = strlen(plg->key);
		unsigned long val;
		if (os_strncasecmp(line, plg->key, len) != 0)
			continue;
		if (!isspace(line[len]) || line[len+1] == 0)
			continue;
		val = strtoul(&line[len+1], NULL, 0);
		if ( (plg->min <= val && val <= plg->max) ||
			 (plg->allow_zero && val == 0))
		{
			unsigned int v = (unsigned int)val;
			*(plg->pval) = v;
			wpa_printf(MSG_DEBUG, "Summit: setting %s to %d", plg->key, v);
			return 0; // success, line was processed
		}
		wpa_printf(MSG_DEBUG, "Summit: invalid config line \"%s\"", line);
		return 0; // failed, line was processed
	}
	return 1; // line was not processed
}

// Summit configuration
int summit_read_config(void)
{
	const int line_size = 256;
	char line[line_size];

	const char *summitGlobals = "/data/Summit/Globals";
	FILE *globals = fopen(summitGlobals, "r");

	summit_init_globals();
	if (globals != NULL) {
		while (fgets(line, sizeof(line), globals)) {
			if (summit_int_globals(line) == 0) {
				; // line processed
			}
		}
		fclose(globals);
	}

	return 0;
}

#endif
