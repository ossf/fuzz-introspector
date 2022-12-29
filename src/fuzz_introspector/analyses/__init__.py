from fuzz_introspector.analyses import calltree_analysis
from fuzz_introspector.analyses import bug_digestor
from fuzz_introspector.analyses import driver_synthesizer
from fuzz_introspector.analyses import engine_input
from fuzz_introspector.analyses import filepath_analyser
from fuzz_introspector.analyses import function_call_analyser
from fuzz_introspector.analyses import metadata
from fuzz_introspector.analyses import optimal_targets
from fuzz_introspector.analyses import runtime_coverage_analysis
from fuzz_introspector.analyses import sinks_analyser

# Ordering here is important as top analysis will be shown first in the report
all_analyses = [
    bug_digestor.BugDigestor,
    calltree_analysis.FuzzCalltreeAnalysis,
    driver_synthesizer.DriverSynthesizer,
    engine_input.EngineInput,
    filepath_analyser.FilePathAnalysis,
    function_call_analyser.ThirdPartyAPICoverageAnalyser,
    metadata.MetadataAnalysis,
    optimal_targets.OptimalTargets,
    runtime_coverage_analysis.RuntimeCoverageAnalysis,
    sinks_analyser.SinkCoverageAnalyser
]
