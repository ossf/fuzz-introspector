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

import soot.MethodOrMethodContext;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Targets;
import soot.options.Options;

public class CallGraphGenerator {
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

		CallGraph callGraph = Scene.v().getCallGraph();
		for(SootClass c : Scene.v().getApplicationClasses()) {
			for(SootMethod m : c.getMethods()){
				Iterator<MethodOrMethodContext> targets = new Targets(callGraph.edgesOutOf(m));
				for ( ; targets.hasNext(); numOfEdges++) {
					SootMethod tgt = (SootMethod) targets.next();
					System.out.println(m + " may call " + tgt);
				}
			}
		}
		System.out.println("Total Edges:" + numOfEdges);
	}

	public List<String> getExcludeList() {
		return excludeList;
	}
}
