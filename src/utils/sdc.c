#include "includes.h"
#include "common.h"
#include "common/defs.h"
#include "utils/sdc.h"

#if defined(_SDC_)

unsigned int sdc_eap_timeout = 10;
unsigned int laird_roam_delta;
unsigned int laird_scan_dwell;
unsigned int laird_scan_delay;
unsigned int laird_scan_passive_dwell;
unsigned int laird_scan_suspend_time;
unsigned int laird_dfs_disable;
#ifdef CONFIG_SDC_DMS
unsigned int laird_dms;
#endif

typedef struct {
	const char *key;
	unsigned int *pval;
	unsigned int def;
	unsigned int min;
	unsigned int max;
	unsigned int allow_zero;
} sLairdGlobal;

static sLairdGlobal lg[] = {
	{ "EAPTIMEOUT", &sdc_eap_timeout, 10, 3, 60, 0 },
	{ "ROAMDELTA", &laird_roam_delta, 0, 0, 10, 1 },
	{ "SCANDWELLTIME", &laird_scan_dwell, 0, 10, 250, 1 },
	{ "SCANDELAYTIME", &laird_scan_delay, 0, 10, 250, 1 },
	{ "SCANPASSIVEDWELLTIME", &laird_scan_passive_dwell, 0, 10, 250, 1 },
	{ "SCANSUSPENDTIME", &laird_scan_suspend_time, 0, 10, 250, 1 },
	{ "DFSDISABLE", &laird_dfs_disable, 0, 0, 1, 1 },
#ifdef CONFIG_SDC_DMS
	{ "DMS", &laird_dms, 0, 0, 6, 1 },
#endif
	{ NULL, NULL, 0, 0, 0, 0 }
};

static void laird_init_globals(void)
{
	sLairdGlobal *plg;
	for (plg=lg; plg->key; plg++) {
		*(plg->pval) = plg->def;
	}
}

static int laird_int_globals(const char *line)
{
	sLairdGlobal *plg;
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
			wpa_printf(MSG_DEBUG, "Laird: setting %s to %d", plg->key, v);
			return 0; // success, line was processed
		}
		wpa_printf(MSG_DEBUG, "Laird: invalid config line \"%s\"", line);
		return 0; // failed, line was processed
	}
	return 1; // line was not processed
}

// Laird configuration
int laird_read_config(void)
{
	const int line_size = 256;
	char line[line_size];

	const char *lairdGlobals = "/data/Laird/Globals";
	FILE *globals = fopen(lairdGlobals, "r");

	laird_init_globals();
	if (globals != NULL) {
		while (fgets(line, sizeof(line), globals)) {
			if (laird_int_globals(line) == 0) {
				; // line processed
			}
		}
		fclose(globals);
	}

	return 0;
}

#endif
