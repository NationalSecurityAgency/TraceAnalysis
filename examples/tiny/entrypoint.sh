#!/bin/bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /app/project MyProject -import tiny
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /app/project MyProject/ -process tiny -scriptPath /app/ghidra_scripts -postScript TraceScript -noanalysis
