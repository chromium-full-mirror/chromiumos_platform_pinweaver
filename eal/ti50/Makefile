# Copyright 2022 The ChromiumOS Authors.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include ../../../ti50/common/build.lib.c.mk

##############################################################################
# Library name
# Default path to library
CLIB_PATH := $(CURDIR)/../..
CLIB_NAME = pinweaver

CLIB_SYM = $(CLIB_PATH)/eal/ti50/$(CLIB_NAME).sym

CFLAGS += -Wno-flexible-array-extensions -Wno-padded
CFLAGS += -I$(CLIB_PATH) -I$(CLIB_PATH)/eal/ti50

# output directory
ODIR := $(BUILD_DIR)
COV_ODIR := $(ODIR)-cov

CLIB_GIT_HASH := "$(shell pushd $(CLIB_PATH) >/dev/null;\
	git describe --always --dirty --exclude '*' ; popd >/dev/null)"

CFLAGS_VERSION := -DCLIB_GIT_HASH=\"$(CLIB_GIT_HASH)\"

SOURCES := pinweaver.c eal/ti50/pinweaver_eal.c

# Intermediate target - native object from LTO parts
CLIB_OBJ = $(ODIR)/$(CLIB_NAME)-native.o
CLIB_LST = $(ODIR)/$(CLIB_NAME)-native.lst
CLIB_OBJSYM = $(ODIR)/$(CLIB_NAME)-clean.o
CLIB_OBJSYMLST = $(ODIR)/$(CLIB_NAME)-clean.lst

# The purpose of this Makefile
FINAL_LIB_NAME := lib$(CLIB_NAME).a
FINAL_LIB := $(BUILD_DIR)/$(FINAL_LIB_NAME)

COV_OBJECTS  = $(patsubst %.c, $(COV_ODIR)/%.o, $(COV_SOURCES))
OBJECTS=$(patsubst %.c, $(ODIR)/%.o, $(SOURCES))
ASM_OBJECTS=$(patsubst %.S, $(ODIR)/%.o, $(ASM_SOURCES))

# Pull in .h dependancies
-include $(OBJECTS:.o=.d)
-include $(COV_OBJECTS:.o=.d)

$(info  Building version $(CLIB_GIT_HASH) in $(CLIB_PATH))
# Use V=1 for verbose output
ifneq ($(V),)
$(info  ********************************************)
$(info  BUILD_DIR      = $(BUILD_DIR))
$(info  FINAL_LIB      = $(FINAL_LIB))
$(info  CC             = $(CC))
$(info  CLIB_PATH      = $(CLIB_PATH))
$(info  SOURCES        = $(SOURCES))
$(info  ASM_SOURCES    = $(ASM_SOURCES))
$(info  OBJECTS        = $(OBJECTS))
$(info  ********************************************)
endif

.PHONY: all
all: $(FINAL_LIB) $(CLIB_OBJ) $(MAKEFILE_LIST) $(OBJECTS)

# this rule builds $(OBJECTS)
$(ODIR)/%.o: $(CLIB_PATH)/%.c $(MAKEFILE_LIST) $(CLIB_HDR)
	@echo "  CC      $(notdir $<)"
	${Q}mkdir -p $(dir $@)
	$(Q)$(CC) -c -o $@ $(CFLAGS) -MMD -MF $@.d $<
	$(Q)$(CC) -S -o $@.S $(CFLAGS) -MMD -MF $@.d $<

$(ODIR)/%.o: $(CLIB_PATH)/%.S $(MAKEFILE_LIST) | $(ODIR)
	@echo "  AS      $(notdir $<)"
	$(Q)$(AS) $(LLVM_AS_FLAGS) -o=$@  $<

$(CLIB_OBJ): $(OBJECTS) $(ASM_OBJECTS) $(COV_OBJECTS) | $(ODIR)
	@echo "  LD      $(notdir $@)"
	$(Q)$(CC) $(CFLAGS_LD_LTO) -Wl,-Map=$@.map -o $@ $^


# Object file with removed internal symbols
$(CLIB_OBJSYM): $(CLIB_OBJ) $(CLIB_SYM) $(MAKEFILE_LIST) | $(ODIR)
	@echo "  OBJCOPY $(notdir $@)"
	$(Q)$(OBJCOPY) --strip-unneeded --localize-hidden \
		--keep-global-symbols=$(CLIB_SYM) $< $@

$(CLIB_OBJSYMLST): $(CLIB_OBJSYM) | $(ODIR)
	@echo "  OBJDUMP $(notdir $@)"
	$(Q)$(OBJDUMP) $(OBJDUMP_FLAGS) $< > $@

#$(FINAL_LIB): $(OBJECTS) $(ASM_OBJECTS)
$(FINAL_LIB): $(CLIB_OBJSYM)
	@echo "  AR      $(notdir $@) in $(dir $@)"
	$(Q)rm -f $@
	$(Q)$(AR) scr $@ $^
	@echo "  OBJDUMP $(notdir $@.lst)"
	$(Q)$(OBJDUMP) $(OBJDUMP_FLAGS) $@ > $@.lst

.PHONY: test
test: $(TEST)
$(TEST): $(TEST_SRC) $(FINAL_LIB)
	@echo "  CC      $(notdir $@)"
	$(Q)$(CC) -o $@ $(CFLAGS_TARGET_TEST) -I include $(TEST_SRC)\
		-L $(BUILD_DIR) -Wl,-l$(CLIB_NAME)
	$(TEST)

################################ CLEAN TARGET #################################
.PHONY: clean
clean:
	$(Q)rm -rf $(OBJECTS) $(COV_OBJECTS)
	$(Q)rm -rf $(BUILD_DIR)

.PHONY: format
format:
	$(Q)find . -path ./config -prune -o \( -iname \*.h -o -iname \*.c \) \
	-exec $(CLANG_FORMAT) -i -style=file {} +
