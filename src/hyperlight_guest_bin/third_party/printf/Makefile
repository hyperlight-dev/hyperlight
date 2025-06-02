# ------------------------------------------------------------------------------
# 
# Generic Makefile
#
# Copyright Marco Paland 2007 - 2017
# Distributed under the MIT License
#
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------------------
PATH_TOOLS_CC        = /usr/bin/
PATH_TOOLS_CC_LIB    = /usr/lib/
PATH_TOOLS_UTIL      = 

PATH_BIN       = bin
PATH_TMP       = tmp
PATH_NUL       = /dev/null
PATH_OBJ       = $(PATH_TMP)/obj
PATH_LST       = $(PATH_TMP)/lst
PATH_ERR       = $(PATH_TMP)/err
PATH_PRE       = $(PATH_TMP)/pre
PATH_COV       = $(PATH_TMP)/cov


# ------------------------------------------------------------------------------
# Application to build
# ------------------------------------------------------------------------------

APP = test_suite


# -----------------------------------------------------------------------------
# Project file list
# Format is:
# FILES_PRJ  = file1                        \
#              foo/file2                    \
#              bar/file3
# -----------------------------------------------------------------------------

FILES_PRJ  = test/test_suite


# ------------------------------------------------------------------------------
# Additional include files and compiler defines
# Format is:
# C_INCLUDES = -Iinclude_path1                 \
#              -Iinclude_path2                 \
#              -Iinclude_path3                 \
# ------------------------------------------------------------------------------

C_INCLUDES = 

C_DEFINES  = 


# ------------------------------------------------------------------------------
# The target name and location
# ------------------------------------------------------------------------------
TRG = $(PATH_BIN)/$(APP)


# ------------------------------------------------------------------------------
# object files
# ------------------------------------------------------------------------------
FILES_TMP   = $(FILES_PRJ)
FILES_O     = $(addsuffix .o, $(FILES_TMP))


# ------------------------------------------------------------------------------
# VPATH definition
#
# VPATH is required for the maker to find the C-/ASM-Source files.
# Extract the directory/module names from the file list with the dir
# command and remove the duplicated directory names with the sort command.
# FILES_PRJ is listed first to make sure that the source files in the project
# directory are searched first.
# ------------------------------------------------------------------------------
VPATH := $(sort $(dir $(FILES_TMP)))


# ------------------------------------------------------------------------------
# Development tools
# ------------------------------------------------------------------------------
AR        = $(PATH_TOOLS_CC)ar
AS        = $(PATH_TOOLS_CC)g++
CC        = $(PATH_TOOLS_CC)g++
CL        = $(PATH_TOOLS_CC)g++
NM        = $(PATH_TOOLS_CC)nm
GCOV      = $(PATH_TOOLS_CC)gcov
OBJDUMP   = $(PATH_TOOLS_CC)objdump
OBJCOPY   = $(PATH_TOOLS_CC)objcopy
READELF   = $(PATH_TOOLS_CC)readelf
SIZE      = $(PATH_TOOLS_CC)size

ECHO      = $(PATH_TOOLS_UTIL)echo
MAKE      = $(PATH_TOOLS_UTIL)make
MKDIR     = $(PATH_TOOLS_UTIL)mkdir
RM        = $(PATH_TOOLS_UTIL)rm
SED       = $(PATH_TOOLS_UTIL)sed


# ------------------------------------------------------------------------------
# Compiler flags for the target architecture
# ------------------------------------------------------------------------------

GCCFLAGS      = $(C_INCLUDES)                     \
                $(C_DEFINES)                      \
                -std=c++11                        \
                -g                                \
                -Wall                             \
                -pedantic                         \
                -Wmain                            \
                -Wundef                           \
                -Wsign-conversion                 \
                -Wuninitialized                   \
                -Wshadow                          \
                -Wunreachable-code                \
                -Wswitch-default                  \
                -Wswitch                          \
                -Wcast-align                      \
                -Wmissing-include-dirs            \
                -Winit-self                       \
                -Wdouble-promotion                \
                -gdwarf-2                         \
                -fno-exceptions                   \
                -O2                               \
                -ffunction-sections               \
                -ffat-lto-objects                 \
                -fdata-sections                   \
                -fverbose-asm                     \
                -Wextra                           \
                -Wunused-parameter                \
                -Wfloat-equal

CFLAGS        = $(GCCFLAGS)                       \
                -Wunsuffixed-float-constants      \
                -x c                              \
                -std=c99

CPPFLAGS      = $(GCCFLAGS)                       \
                -x c++                            \
                -fno-rtti                         \
                -fstrict-enums                    \
                -fno-use-cxa-atexit               \
                -fno-use-cxa-get-exception-ptr    \
                -fno-nonansi-builtins             \
                -fno-threadsafe-statics           \
                -fno-enforce-eh-specs             \
                -ftemplate-depth-64               \
                -fexceptions

AFLAGS        = $(GCCFLAGS)                       \
                -x assembler

LFLAGS        = $(GCCFLAGS)                       \
                -x none                           \
                -Wl,--gc-sections

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Main-Dependencies (app: all)
# ------------------------------------------------------------------------------
.PHONY: all
all: clean_prj $(TRG) $(TRG)_nm.txt


# ------------------------------------------------------------------------------
# Main-Dependencies (app: rebuild)
# ------------------------------------------------------------------------------
.PHONY: rebuild
rebuild: clean $(TRG) $(TRG)_nm.txt


# ------------------------------------------------------------------------------
# clean project
# ------------------------------------------------------------------------------
.PHONY: clean_prj
clean_prj:
	@-$(ECHO) +++ cleaning project
	@-$(RM) -rf $(PATH_BIN) 2> $(PATH_NUL)
	@-$(MKDIR) -p $(PATH_BIN)
	@-$(MKDIR) -p $(PATH_OBJ)
	@-$(MKDIR) -p $(PATH_ERR)
	@-$(MKDIR) -p $(PATH_LST)
	@-$(MKDIR) -p $(PATH_PRE)
	@-$(MKDIR) -p $(PATH_COV)


# ------------------------------------------------------------------------------
# clean all
# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	@-$(ECHO) +++ cleaning all
	@-$(RM) -rf $(PATH_BIN) 2> $(PATH_NUL)
	@-$(RM) -rf $(PATH_TMP) 2> $(PATH_NUL)
	@-$(MKDIR) -p $(PATH_BIN)
	@-$(MKDIR) -p $(PATH_OBJ)
	@-$(MKDIR) -p $(PATH_ERR)
	@-$(MKDIR) -p $(PATH_LST)
	@-$(MKDIR) -p $(PATH_COV)


# ------------------------------------------------------------------------------
# print the GNUmake version and the compiler version
# ------------------------------------------------------------------------------
.PHONY: version
version:
  # Print the GNU make version and the compiler version
	@$(ECHO) GNUmake version:
	@$(MAKE) --version
	@$(ECHO) GCC version:
	@$(CL) -v


# ------------------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Link/locate application
# ------------------------------------------------------------------------------
$(TRG) : $(FILES_O)
	@-$(ECHO) +++ linkink application to generate: $(TRG)
	@-$(CL) $(LFLAGS) -L. -lc $(PATH_OBJ)/*.o -Wl,-Map,$(TRG).map -o $(TRG)
  # profiling
	@-$(CL) $(LFLAGS) -L. -lc $(PATH_COV)/*.o --coverage -o $(PATH_COV)/$(APP)


# ------------------------------------------------------------------------------
# parse the object files to obtain symbol information, and create a size summary
# ------------------------------------------------------------------------------
$(TRG)_nm.txt : $(TRG)
	@-$(ECHO) +++ parsing symbols with nm to generate: $(TRG)_nm.txt
	@-$(NM) --numeric-sort --print-size $(TRG) > $(TRG)_nm.txt
	@-$(ECHO) +++ demangling symbols with c++filt to generate: $(TRG)_cppfilt.txt
	@-$(NM) --numeric-sort --print-size $(TRG) | $(CPPFILT) > $(TRG)_cppfilt.txt
	@-$(ECHO) +++ creating size summary table with size to generate: $(TRG)_size.txt
	@-$(SIZE) -A -t $(TRG) > $(TRG)_size.txt


%.o : %.cpp
	@$(ECHO) +++ compile: $<
  # Compile the source file
  # ...and Reformat (using sed) any possible error/warning messages for the VisualStudio(R) output window
  # ...and Create an assembly listing using objdump
  # ...and Generate a dependency file (using the -MM flag)
	@-$(CL) $(CPPFLAGS) $< -E -o $(PATH_PRE)/$(basename $(@F)).pre
	@-$(CL) $(CPPFLAGS) $< -c -o $(PATH_OBJ)/$(basename $(@F)).o 2> $(PATH_ERR)/$(basename $(@F)).err
	@-$(SED) -e 's|.h:\([0-9]*\),|.h(\1) :|' -e 's|:\([0-9]*\):|(\1) :|' $(PATH_ERR)/$(basename $(@F)).err
	@-$(OBJDUMP) --disassemble --line-numbers -S $(PATH_OBJ)/$(basename $(@F)).o > $(PATH_LST)/$(basename $(@F)).lst
	@-$(CL) $(CPPFLAGS) $< -MM > $(PATH_OBJ)/$(basename $(@F)).d
  # profiling
	@-$(CL) $(CPPFLAGS) -O0 --coverage $< -c -o $(PATH_COV)/$(basename $(@F)).o 2> $(PATH_NUL)

%.o : %.c
	@$(ECHO) +++ compile: $<
  # Compile the source file
  # ...and Reformat (using sed) any possible error/warning messages for the VisualStudio(R) output window
  # ...and Create an assembly listing using objdump
  # ...and Generate a dependency file (using the -MM flag)
	@-$(CL) $(CFLAGS) $< -E -o $(PATH_PRE)/$(basename $(@F)).pre
	@-$(CC) $(CFLAGS) $< -c -o $(PATH_OBJ)/$(basename $(@F)).o 2> $(PATH_ERR)/$(basename $(@F)).err
	@-$(SED) -e 's|.h:\([0-9]*\),|.h(\1) :|' -e 's|:\([0-9]*\):|(\1) :|' $(PATH_ERR)/$(basename $(@F)).err
	@-$(OBJDUMP) -S $(PATH_OBJ)/$(basename $(@F)).o > $(PATH_LST)/$(basename $(@F)).lst
	@-$(CC) $(CFLAGS) $< -MM > $(PATH_OBJ)/$(basename $(@F)).d
