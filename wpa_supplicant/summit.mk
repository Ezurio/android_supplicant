# Summit android <android.mk> changes
ifdef CONFIG_SDC
L_CFLAGS += -D_SDC_
OBJS += src/utils/sdc.c
endif
ifdef CONFIG_WNM
ifdef CONFIG_SDC_DMS
L_CFLAGS += -DCONFIG_SDC_DMS
endif
endif
ifdef CONFIG_SDC_RADIO_MVL60
L_CFLAGS += -DCONFIG_SDC_RADIO_MVL60
endif
