# This file is generated by gyp; do not edit.

TOOLSET := target
TARGET := ffi_bindings
DEFS_Debug := \
	'-DNODE_GYP_MODULE_NAME=ffi_bindings' \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-DBUILDING_NODE_EXTENSION' \
	'-DDEBUG' \
	'-D_DEBUG'

# Flags passed to all source files.
CFLAGS_Debug := \
	-fPIC \
	-pthread \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-m64 \
	-g \
	-O0

# Flags passed to only C files.
CFLAGS_C_Debug :=

# Flags passed to only C++ files.
CFLAGS_CC_Debug := \
	-fno-rtti \
	-fno-exceptions

INCS_Debug := \
	-I/home/vagrant/.node-gyp/0.12.7/src \
	-I/home/vagrant/.node-gyp/0.12.7/deps/uv/include \
	-I/home/vagrant/.node-gyp/0.12.7/deps/v8/include \
	-I$(srcdir)/../nan \
	-I$(srcdir)/deps/libffi/include \
	-I$(srcdir)/deps/libffi/config/linux/x64

DEFS_Release := \
	'-DNODE_GYP_MODULE_NAME=ffi_bindings' \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-DBUILDING_NODE_EXTENSION'

# Flags passed to all source files.
CFLAGS_Release := \
	-fPIC \
	-pthread \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-m64 \
	-O3 \
	-ffunction-sections \
	-fdata-sections \
	-fno-tree-vrp \
	-fno-omit-frame-pointer

# Flags passed to only C files.
CFLAGS_C_Release :=

# Flags passed to only C++ files.
CFLAGS_CC_Release := \
	-fno-rtti \
	-fno-exceptions

INCS_Release := \
	-I/home/vagrant/.node-gyp/0.12.7/src \
	-I/home/vagrant/.node-gyp/0.12.7/deps/uv/include \
	-I/home/vagrant/.node-gyp/0.12.7/deps/v8/include \
	-I$(srcdir)/../nan \
	-I$(srcdir)/deps/libffi/include \
	-I$(srcdir)/deps/libffi/config/linux/x64

OBJS := \
	$(obj).target/$(TARGET)/src/ffi.o \
	$(obj).target/$(TARGET)/src/callback_info.o \
	$(obj).target/$(TARGET)/src/threaded_callback_invokation.o

# Add to the list of files we specially track dependencies for.
all_deps += $(OBJS)

# Make sure our dependencies are built before any of us.
$(OBJS): | $(builddir)/libffi.a $(obj).target/deps/libffi/libffi.a

# CFLAGS et al overrides must be target-local.
# See "Target-specific Variable Values" in the GNU Make manual.
$(OBJS): TOOLSET := $(TOOLSET)
$(OBJS): GYP_CFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_C_$(BUILDTYPE))
$(OBJS): GYP_CXXFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_CC_$(BUILDTYPE))

# Suffix rules, putting all outputs into $(obj).

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(srcdir)/%.cc FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# Try building from generated source, too.

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj).$(TOOLSET)/%.cc FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj)/%.cc FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# End of this set of suffix rules
### Rules for final target.
LDFLAGS_Debug := \
	-pthread \
	-rdynamic \
	-m64

LDFLAGS_Release := \
	-pthread \
	-rdynamic \
	-m64

LIBS :=

$(obj).target/ffi_bindings.node: GYP_LDFLAGS := $(LDFLAGS_$(BUILDTYPE))
$(obj).target/ffi_bindings.node: LIBS := $(LIBS)
$(obj).target/ffi_bindings.node: TOOLSET := $(TOOLSET)
$(obj).target/ffi_bindings.node: $(OBJS) $(obj).target/deps/libffi/libffi.a FORCE_DO_CMD
	$(call do_cmd,solink_module)

all_deps += $(obj).target/ffi_bindings.node
# Add target alias
.PHONY: ffi_bindings
ffi_bindings: $(builddir)/ffi_bindings.node

# Copy this to the executable output path.
$(builddir)/ffi_bindings.node: TOOLSET := $(TOOLSET)
$(builddir)/ffi_bindings.node: $(obj).target/ffi_bindings.node FORCE_DO_CMD
	$(call do_cmd,copy)

all_deps += $(builddir)/ffi_bindings.node
# Short alias for building this executable.
.PHONY: ffi_bindings.node
ffi_bindings.node: $(obj).target/ffi_bindings.node $(builddir)/ffi_bindings.node

# Add executable to "all" target.
.PHONY: all
all: $(builddir)/ffi_bindings.node

