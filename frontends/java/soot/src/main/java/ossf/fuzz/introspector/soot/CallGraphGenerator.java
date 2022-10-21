
// Copyright 2022 Fuzz Introspector Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
///////////////////////////////////////////////////////////////////////////

package ossf.fuzz.introspector.soot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import ossf.fuzz.introspector.soot.yaml.BranchProfile;
import ossf.fuzz.introspector.soot.yaml.BranchSide;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import ossf.fuzz.introspector.soot.yaml.FuzzerConfig;
import soot.Body;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.internal.JIfStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

public class CallGraphGenerator{
	public static void main(String[] args) {
		if (args.length != 3) {
			System.err.println("No jarFiles, entryClass or entryMethod.");
			return;
		}
		List<String> jarFiles = Arrays.asList(args[0].split(":"));
		String entryClass = args[1];
		String entryMethod = args[2];

		if (jarFiles.size() < 1) {
			System.err.println("Invalid jarFiles");
		}

		soot.G.reset();

		// Add an custom analysis phase to Soot
		CustomSenceTransformer custom = new CustomSenceTransformer(entryClass, entryMethod);
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.custom", custom));

		// Set basic settings for the call graph generation
		Options.v().set_process_dir(jarFiles);
		Options.v().set_prepend_classpath(true);
		Options.v().set_src_prec(Options.src_prec_java);
		Options.v().set_exclude(custom.getExcludeList());
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_whole_program(true);
		Options.v().set_keep_line_number(true);

		// Load and set main class
		Options.v().set_main_class(entryClass);
		SootClass c = Scene.v().loadClass(entryClass, SootClass.BODIES);
		c.setApplicationClass();

		// Load and set custom entry point
		SootMethod entryPoint = c.getMethodByName(entryMethod);
		List<SootMethod> entryPoints = new ArrayList<SootMethod>();
		entryPoints.add(entryPoint);
		Scene.v().setEntryPoints(entryPoints);

		// Load all related classes
		Scene.v().loadNecessaryClasses();

		// Start the generation
		PackManager.v().runPacks();
	}
}

class CustomSenceTransformer extends SceneTransformer {
	private List<String> excludeList;
	private String entryClass;
	private String entryMethod;
	private List<Block> visitedBlock;

	public CustomSenceTransformer(String entryClass, String entryMethod) {
		this.entryClass = entryClass;
		this.entryMethod = entryMethod;

		excludeList = new LinkedList<String> ();

		excludeList.add("jdk.");
		excludeList.add("java.");
		excludeList.add("javax.");
		excludeList.add("sun.");
		excludeList.add("sunw.");
		excludeList.add("com.sun.");
		excludeList.add("com.ibm.");
		excludeList.add("com.apple.");
		excludeList.add("apple.awt.");
	}

	@Override
	protected void internalTransform(String phaseName, Map<String, String> options) {
		Map<String, SootMethod> methodMap = new HashMap<String, SootMethod>();
		List<FuzzerConfig> classYaml = new ArrayList<FuzzerConfig>();

		// Extract Callgraph for the included Java Class
		CallGraph callGraph = Scene.v().getCallGraph();
		for(SootClass c : Scene.v().getApplicationClasses()) {
			if (c.getName().startsWith("jdk")) {
				continue;
			}

			// Discover class related information
			FuzzerConfig classConfig = new FuzzerConfig();
			FunctionConfig methodConfig = new FunctionConfig();
			classConfig.setFilename(c.getName());
			methodConfig.setListName("All functions");

			// Loop through each methods in the class
			for (SootMethod m : c.getMethods()) {
				// Discover method related information
				FunctionElement element= new FunctionElement();

				// Unable to retrieve from Soot
				//element.setLinkageType("???");
				//element.setConstantsTouched([]);
				//element.setArgNames();

				element.setFunctionName(m.getName());
				element.setFunctionSourceFile(c.getFilePath());
				element.setFunctionLinenumber(m.getJavaSourceStartLineNumber());
				element.setReturnType(m.getReturnType().toString());
				element.setArgCount(m.getParameterCount());
				for (soot.Type type:m.getParameterTypes()) {
					element.addArgType(type.toString());
				}

				// Identify in / out edges of each method.
				int methodEdges = 0;
				Iterator<Edge> outEdges = callGraph.edgesOutOf(m);
				Iterator<Edge> inEdges = callGraph.edgesInto(m);
				while (inEdges.hasNext()) {
					methodEdges++;
					inEdges.next();
				}
				element.setFunctionUses(methodEdges);
				methodEdges = 0;
				for ( ; outEdges.hasNext(); methodEdges++) {
					Edge edge = outEdges.next();
					SootMethod tgt = (SootMethod) edge.getTgt();
					element.addFunctionReached(tgt.toString() + "; Line: " +
							edge.srcStmt().getJavaSourceStartLineNumber());
				}
				element.setEdgeCount(methodEdges);

				// Identify blocks information
				Body methodBody = m.retrieveActiveBody();
				BlockGraph blockGraph = new BriefBlockGraph(methodBody);

				element.setBBCount(blockGraph.size());
				int iCount = 0;
				for (Block block:blockGraph.getBlocks()) {
					Iterator<Unit> blockIt = block.iterator();
					while(blockIt.hasNext()) {
						Unit unit = blockIt.next();
						if (unit instanceof JIfStmt) {
							// Handle branch profile
							BranchProfile branchProfile = new BranchProfile();
							BranchSide branchSide = new BranchSide();

							Map<String, Integer> trueBlockLine =
									getBlockStartEndLineWithLineNumber(blockGraph.getBlocks(), unit.getJavaSourceStartLineNumber() + 1);
							Map<String, Integer> falseBlockLine =
									getBlockStartEndLineWithLineNumber(blockGraph.getBlocks(),
											((JIfStmt)unit).getUnitBoxes().get(0).getUnit().getJavaSourceStartLineNumber());

							// True branch
							if (!trueBlockLine.isEmpty()) {
								Integer start = trueBlockLine.get("start");
								Integer end = trueBlockLine.get("end");
								branchSide.setTrueSides(c.getName() + ":" + start);
								branchSide.setTrueSidesFuncs(getFunctionCallInTargetLine(
										element.getFunctionReached(), start, end));

							}

							// False branch
							if (!falseBlockLine.isEmpty()) {
								Integer start = falseBlockLine.get("start");
								Integer end = falseBlockLine.get("end");
								branchSide.setFalseSides(c.getName() + ":" + (start - 1));
								branchSide.setFalseSidesFuncs(getFunctionCallInTargetLine(
										element.getFunctionReached(), start, end));
							}

							branchProfile.setBranchString(c.getName() + ":" + unit.getJavaSourceStartLineNumber());
							branchProfile.setBranchSides(branchSide);
							element.addBranchProfile(branchProfile);
						}
						iCount++;
					}
				}
				element.setiCount(iCount);

				visitedBlock = new ArrayList<Block>();
				visitedBlock.addAll(blockGraph.getTails());
				element.setCyclomaticComplexity(calculateCyclomaticComplexity(
						blockGraph.getHeads(), 0));

				methodConfig.addFunctionElement(element);

				// Only methods in the entry class or method reachable
				// from the entry method in the entry class are included
				// in the call graph result.
				if (c.getName().equals(this.entryClass) ||
						element.getFunctionUses() > 0) {
					methodMap.put(c.getName() + "#" + m.getName(), m);
				}
			}
			classConfig.setFunctionConfig(methodConfig);
			classYaml.add(classConfig);
		}
		System.out.println("Call Tree");
		System.out.println(extractCallTree(callGraph,
				this.entryClass + "#" + this.entryMethod,
				methodMap, 0, -1));
		System.out.println("--------------------------------------------------");
		ObjectMapper om = new ObjectMapper(new YAMLFactory());
		for(FuzzerConfig config:classYaml) {
			try {
				System.out.println(om.writeValueAsString(config) + "\n");
			} catch (JsonProcessingException e) {
				e.printStackTrace();
			}
		}
	}

	// Recursively extract calltree from stored method relationship
	private String extractCallTree(CallGraph cg, String index, Map<String, SootMethod> methodMap, Integer depth, Integer line) {
		SootMethod m = methodMap.get(index);
		String[] name = index.split("#");
		if (m == null) {
			return StringUtils.leftPad("", depth * 2) + name[1] + " " + name[0] + " linenumber=" + line + "\n";
		} else {
			StringBuffer callTree = new StringBuffer();
			Iterator<Edge> outEdges = cg.edgesOutOf(m);

			callTree.append(StringUtils.leftPad("", depth * 2));
			callTree.append(name[1] + " " + name[0] + " linenumber=" + line + "\n");

			while (outEdges.hasNext()) {
				Edge edge = outEdges.next();
				SootMethod tgt = (SootMethod) edge.getTgt();
				callTree.append(extractCallTree(cg,
						tgt.getDeclaringClass().getName() + "#" + tgt.getName(),
						methodMap, depth + 1, edge.srcStmt().getJavaSourceStartLineNumber()));
			}

			return callTree.toString();
		}
	}

	private Integer calculateCyclomaticComplexity(List<Block> start, Integer complexity) {
		for (Block block:start) {
			if (visitedBlock.contains(block)) {
				complexity += 1;
			} else {
				visitedBlock.add(block);
				complexity = calculateCyclomaticComplexity(block.getSuccs(), complexity);
			}
		}
		return complexity;
	}

	private Map<String, Integer> getBlockStartEndLineWithLineNumber(List<Block> blocks, Integer lineNumber) {
		Integer startLine;
		Integer endLine;

		for (Block block:blocks) {
			Iterator<Unit> it = block.iterator();
			startLine = -1;
			endLine = -1;
			while(it.hasNext()) {
				Unit unit = it.next();
				if (startLine == -1) {
					startLine = unit.getJavaSourceStartLineNumber();
				}
				endLine = unit.getJavaSourceStartLineNumber();
			}
			if (lineNumber >= startLine && lineNumber <= endLine) {
				Map<String, Integer> line = new HashMap<String, Integer>();
				line.put("start", startLine);
				line.put("end", endLine);
				return line;
			}
		}

		return Collections.emptyMap();
	}

	private List<String> getFunctionCallInTargetLine(List<String> functionReached, Integer startLine, Integer endLine) {
		List<String> targetFunctionList = new ArrayList<String>();

		for (String func: functionReached) {
			String[] line = func.split(" Line: ");
			Integer lineNumber = Integer.parseInt(line[1]);
			if (lineNumber >= startLine && lineNumber <= endLine) {
				targetFunctionList.add(line[0]);
			}
		}

		return targetFunctionList;
	}

	public List<String> getExcludeList() {
		return excludeList;
	}
}
