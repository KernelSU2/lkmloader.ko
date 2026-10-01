obj := $(src)/out

MODULE_NAME := mylkm
$(MODULE_NAME)-objs := core.o
obj-m := $(MODULE_NAME).o
$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(M))
$(info -- src: $(src))
$(info -- obj: $(obj))

lkmloader-objs := loader.o
obj-m += lkmloader.o

ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-int-conversion
ccflags-y += -Wno-unused-result
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-builtin-macro-redefined
ccflags-y += -Wno-strict-prototypes
ccflags-y += -I$(srctree)

# kbuild 6.10+ fix (ddk): allow $(obj) != $(src) out-of-tree builds
$(obj)/%.o: $(src)/%.c $(recordmcount_source) FORCE
	$(call if_changed_rule,cc_o_c)
	$(call cmd,force_checksrc)
ccflags-y += -Wno-missing-prototypes
