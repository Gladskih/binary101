Unicode true
Name "Binary101 gallery sample"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Binary101 Gallery"
RequestExecutionLevel user
SetCompressor /SOLID zlib

Section
  SetOutPath "$INSTDIR"
  File "hello.txt"
SectionEnd
