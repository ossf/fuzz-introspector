from fuzz_introspector.analyses import bug_digestor
from fuzz_introspector.analyses import driver_synthesizer
from fuzz_introspector.analyses import engine_input
from fuzz_introspector.analyses import filepath_analyser
from fuzz_introspector.analyses import function_call_analyser
from fuzz_introspector.analyses import metadata
from fuzz_introspector.analyses import optimal_targets
from fuzz_introspector.analyses import runtime_coverage_analysis
from fuzz_introspector.analyses import sinks_analyser

# All optional analyses.
# Ordering here is important as top analysis will be shown first in the report
all_analyses = [
    optimal_targets.OptimalTargets, engine_input.EngineInput,
    runtime_coverage_analysis.RuntimeCoverageAnalysis,
    driver_synthesizer.DriverSynthesizer, bug_digestor.BugDigestor,
    filepath_analyser.FilePathAnalysis,
    function_call_analyser.ThirdPartyAPICoverageAnalyser,
    metadata.MetadataAnalysis, sinks_analyser.SinkCoverageAnalyser
]
