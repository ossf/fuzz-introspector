add_llvm_component_library( LLVMInspector
  Inspector.cpp

  PLUGIN_TOOL
  opt

  DEPENDS
  intrinsics_gen
  )
