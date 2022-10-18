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

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import ossf.fuzz.introspector.soot.yaml.FuzzerConfig;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;

public class CallGraphGenerator
 {
	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("No entryClass or entryMethod.");
			return;
		}
		String entryClass = args[0];
		String entryMethod = args[1];

		// Set basic Java class path
		String javapath = System.getProperty("java.class.path");
		String jredir = System.getProperty("java.home")+"/lib/rt.jar";
		String path = javapath+File.pathSeparator+jredir;
		Scene.v().setSootClassPath(path);

		// Add an custom analysis phase to Soot
		CustomSenceTransformer custom = new CustomSenceTransformer();
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.custom", custom));

		// Set basic settings for the call graph generation
		Options.v().set_exclude(custom.getExcludeList());
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_whole_program(true);
		Options.v().set_app(true);
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

	public CustomSenceTransformer() {
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
		int numOfEdges = 0;
		int numOfClasses = 0;
		int numOfMethods = 0;
		List<FuzzerConfig> classYaml = new ArrayList<FuzzerConfig>();

		CallGraph callGraph = Scene.v().getCallGraph();
		System.out.println("--------------------------------------------------");
		for(SootClass c : Scene.v().getApplicationClasses()) {
			if (c.getName().startsWith("jdk")) {
				continue;
			}

			FuzzerConfig classConfig = new FuzzerConfig();
			FunctionConfig methodConfig = new FunctionConfig();
			classConfig.setFilename(c.getName());
			methodConfig.setListName("All functions");

			numOfClasses++;
			System.out.println("Class #" + numOfClasses + ": " + c.getName());
			for (SootMethod m : c.getMethods()) {
				FunctionElement element= new FunctionElement();
				element.setFunctionName(m.getName());
				element.setFunctionSourceFile(c.getFilePath());
				//element.setLinkageType("???");
				element.setFunctionLinenumber(m.getJavaSourceStartLineNumber());
				element.setReturnType(m.getReturnType().toString());
				element.setArgCount(m.getParameterCount());
				for (soot.Type type:m.getParameterTypes()) {
					element.addArgType(type.toString());
				}
				//element.setConstantsTouched([]);
				//element.setArgNames();
				//element.setBBCount(0);
				//element.setiCount(0);
				//element.setCyclomaticComplexity(0);

				numOfMethods++;
				int methodEdges = 0;
				Iterator<Edge> outEdges = callGraph.edgesOutOf(m);
				Iterator<Edge> inEdges = callGraph.edgesInto(m);
				System.out.println("Class #" + numOfClasses + " Method #" +
						numOfMethods + ": " + m);

				if (!inEdges.hasNext()) {
					System.out.println("\t > No calls to this method.");
				}

				for ( ; inEdges.hasNext(); methodEdges++) {
					Edge edge = inEdges.next();
					SootMethod src = (SootMethod) edge.getSrc();
					System.out.println("\t > called by " + src + " on Line " +
							edge.srcStmt().getJavaSourceStartLineNumber());
				}

				System.out.println("\n\t Total: " + methodEdges + " internal calls.\n");

				element.setFunctionUses(methodEdges);
				methodEdges = 0;

				if (!outEdges.hasNext()) {
					System.out.println("\t > No calls from this method.");
				}

				for ( ; outEdges.hasNext(); methodEdges++) {
					Edge edge = outEdges.next();
					SootMethod tgt = (SootMethod) edge.getTgt();
					System.out.println("\t > calls " + tgt + " on Line " +
							edge.srcStmt().getJavaSourceStartLineNumber());
					element.addFunctionReached(tgt.toString() + "; Line: " +
							edge.srcStmt().getJavaSourceStartLineNumber());
				}
				System.out.println("\n\t Total: " + methodEdges + " external calls.\n");
				numOfEdges += methodEdges;

				element.setEdgeCount(methodEdges);
				//element.setBranchProfiles(new BranchProfile());
				methodConfig.addFunctionElement(element);
			}
			System.out.println("--------------------------------------------------");
			classConfig.setFunctionConfig(methodConfig);
			classYaml.add(classConfig);
		}
		System.out.println("Total Edges:" + numOfEdges);
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

	public List<String> getExcludeList() {
		return excludeList;
	}
}

