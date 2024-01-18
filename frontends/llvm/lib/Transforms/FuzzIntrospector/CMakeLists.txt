add_llvm_component_library( LLVMFuzzIntrospector
  FuzzIntrospector.cpp

  PLUGIN_TOOL
  opt

  DEPENDS
  intrinsics_gen
  LLVMBinaryFormat
  )
