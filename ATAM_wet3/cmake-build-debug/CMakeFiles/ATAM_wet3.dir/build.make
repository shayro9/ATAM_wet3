﻿# CMAKE generated file: DO NOT EDIT!
# Generated by "NMake Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE
NULL=nul
!ENDIF
SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files\JetBrains\CLion 2021.2.3\bin\cmake\win\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files\JetBrains\CLion 2021.2.3\bin\cmake\win\bin\cmake.exe" -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles\ATAM_wet3.dir\depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles\ATAM_wet3.dir\compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles\ATAM_wet3.dir\progress.make

# Include the compile flags for this target's objects.
include CMakeFiles\ATAM_wet3.dir\flags.make

CMakeFiles\ATAM_wet3.dir\main.c.obj: CMakeFiles\ATAM_wet3.dir\flags.make
CMakeFiles\ATAM_wet3.dir\main.c.obj: ..\main.c
CMakeFiles\ATAM_wet3.dir\main.c.obj: CMakeFiles\ATAM_wet3.dir\compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/ATAM_wet3.dir/main.c.obj"
	$(CMAKE_COMMAND) -E cmake_cl_compile_depends --dep-file=CMakeFiles\ATAM_wet3.dir\main.c.obj.d --working-dir=C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug --filter-prefix="Note: including file: " -- C:\PROGRA~2\MICROS~3\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx86\x86\cl.exe @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) /showIncludes /FoCMakeFiles\ATAM_wet3.dir\main.c.obj /FdCMakeFiles\ATAM_wet3.dir\ /FS -c C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\main.c
<<

CMakeFiles\ATAM_wet3.dir\main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ATAM_wet3.dir/main.c.i"
	C:\PROGRA~2\MICROS~3\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx86\x86\cl.exe > CMakeFiles\ATAM_wet3.dir\main.c.i @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\main.c
<<

CMakeFiles\ATAM_wet3.dir\main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ATAM_wet3.dir/main.c.s"
	C:\PROGRA~2\MICROS~3\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx86\x86\cl.exe @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) /FoNUL /FAs /FaCMakeFiles\ATAM_wet3.dir\main.c.s /c C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\main.c
<<

# Object files for target ATAM_wet3
ATAM_wet3_OBJECTS = \
"CMakeFiles\ATAM_wet3.dir\main.c.obj"

# External object files for target ATAM_wet3
ATAM_wet3_EXTERNAL_OBJECTS =

ATAM_wet3.exe: CMakeFiles\ATAM_wet3.dir\main.c.obj
ATAM_wet3.exe: CMakeFiles\ATAM_wet3.dir\build.make
ATAM_wet3.exe: CMakeFiles\ATAM_wet3.dir\objects1.rsp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ATAM_wet3.exe"
	"C:\Program Files\JetBrains\CLion 2021.2.3\bin\cmake\win\bin\cmake.exe" -E vs_link_exe --intdir=CMakeFiles\ATAM_wet3.dir --rc=C:\PROGRA~2\WI3CF2~1\10\bin\100190~1.0\x86\rc.exe --mt=C:\PROGRA~2\WI3CF2~1\10\bin\100190~1.0\x86\mt.exe --manifests -- C:\PROGRA~2\MICROS~3\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx86\x86\link.exe /nologo @CMakeFiles\ATAM_wet3.dir\objects1.rsp @<<
 /out:ATAM_wet3.exe /implib:ATAM_wet3.lib /pdb:C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug\ATAM_wet3.pdb /version:0.0 /machine:X86 /debug /INCREMENTAL /subsystem:console  kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib 
<<

# Rule to build all files generated by this target.
CMakeFiles\ATAM_wet3.dir\build: ATAM_wet3.exe
.PHONY : CMakeFiles\ATAM_wet3.dir\build

CMakeFiles\ATAM_wet3.dir\clean:
	$(CMAKE_COMMAND) -P CMakeFiles\ATAM_wet3.dir\cmake_clean.cmake
.PHONY : CMakeFiles\ATAM_wet3.dir\clean

CMakeFiles\ATAM_wet3.dir\depend:
	$(CMAKE_COMMAND) -E cmake_depends "NMake Makefiles" C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3 C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3 C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug C:\Users\shayr\Documents\GitHub\ATAM_wet3\ATAM_wet3\cmake-build-debug\CMakeFiles\ATAM_wet3.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles\ATAM_wet3.dir\depend
