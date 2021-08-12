# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

ifneq ($(V),)
  Q :=
else
  Q := @
endif

# we need clang because gtest is built with clang
CC = clang
CXX = clang++
MKDIR ?= mkdir

BUILD_PATH = $(abspath $(CURDIR)/build)
TOP_PATH = $(abspath $(CURDIR)/../../../..)
TPM_STORAGE_PATH = $(TOP_PATH)/eal/tpm_storage
MINI_TRUNKS_PATH = $(TPM_STORAGE_PATH)/mini_trunks

TARGET = $(BUILD_PATH)/mini_trunks_test
TARGET_PROFRAW = $(TARGET).profraw
TARGET_PROFDATA = $(TARGET).profdata
COV_REPORT = $(BUILD_PATH)/coverage_report.html
TESTED_SRCS = tss.c authorization_delegate.c hmac_authorization_delegate.c
SRCS = $(TESTED_SRCS) mini_trunks_fuzzer.cc fuzzed_eal.cc
TESTED_OBJS = $(TESTED_SRCS:%.c=$(BUILD_PATH)/%.o)
OBJS = $(filter %.o,$(SRCS:%.c=$(BUILD_PATH)/%.o))
OBJS += $(filter %.o,$(SRCS:%.cc=$(BUILD_PATH)/%.o))
INCLUDES = -I$(MINI_TRUNKS_PATH) -I$(TPM_STORAGE_PATH) -I$(TOP_PATH)
FUZZER_FLAGS = -fsanitize=fuzzer,address,undefined -fprofile-instr-generate \
	-fcoverage-mapping
OPTIONS = -g -O3 $(FUZZER_FLAGS)
CXXOPTIONS = $(OPTIONS) -std=c++11
LDFLAGS += $(FUZZER_FLAGS)
LIBS = -lgcov -lstdc++ -lssl -lcrypto
DEPS = Makefile

.PHONY: all build clean cov run
.DEFAULT: all

all: run cov

build: $(TARGET)

clean:
	$(RM) -rf $(BUILD_PATH)

run: $(TARGET_PROFRAW)

cov: $(COV_REPORT)
	$(Q)llvm-cov report $(TESTED_OBJS) --instr-profile=$(TARGET_PROFDATA) \
		--ignore-filename-regex=".*\.h"

$(TARGET): $(BUILD_PATH) $(OBJS)
	@echo "  BIN $@"
	$(Q)$(CC) -o $@ $(OBJS) -L/usr/lib64 $(LDFLAGS) -L$(BUILD_PATH) $(LIBS)

$(COV_REPORT): $(TARGET) $(TARGET_PROFDATA)
	$(Q)llvm-cov show $(TESTED_OBJS) --instr-profile=$(TARGET_PROFDATA) \
		--format=html > $(COV_REPORT)

$(TARGET_PROFDATA): $(TARGET_PROFRAW)
	$(Q)llvm-profdata merge -sparse $(TARGET_PROFRAW) -o $(TARGET_PROFDATA)

.PRECIOUS: $(TARGET_PROFRAW)
$(TARGET_PROFRAW): $(TARGET)
	$(Q)LLVM_PROFILE_FILE=$(TARGET_PROFRAW) $(TARGET) -timeout=10 \
		-ignore_ooms=false -ignore_timeouts=false -use_value_profile=true \
		-fork=1

$(BUILD_PATH):
	$(Q)$(MKDIR) -p $@

vpath %.c $(MINI_TRUNKS_PATH)

$(BUILD_PATH)/%.o: %.c $(DEPS)
	@echo "  CC $@"
	$(Q)$(CC) -c $< -o $@ $(CFLAGS) $(OPTIONS) $(INCLUDES)

$(BUILD_PATH)/%.o: %.cc $(DEPS)
	@echo "  CPP $@"
	$(Q)$(CXX) -c -o $@ $< $(CXXFLAGS) $(CXXOPTIONS) $(INCLUDES)
