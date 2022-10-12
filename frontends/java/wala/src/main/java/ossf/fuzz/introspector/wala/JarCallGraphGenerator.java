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

package ossf.fuzz.introspector.wala;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.core.util.strings.StringStuff;
import com.ibm.wala.ipa.callgraph.AnalysisCache;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.CallGraphBuilder;
import com.ibm.wala.ipa.callgraph.CallGraphBuilderCancelException;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.ISSABasicBlock;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.util.io.CommandLine;

public class JarCallGraphGenerator {
	public static void main(String[] args) throws IOException, ClassHierarchyException, IllegalArgumentException,
	CallGraphBuilderCancelException {
		Properties p = CommandLine.parse(args);
		String jarFile = p.getProperty("jarFile");
		String entryClass = p.getProperty("entryClass");
		System.out.println("jarFile: " + FileSystems.getDefault().getPath(jarFile).toAbsolutePath());
		System.out.println("entryClass: " + entryClass);

		AnalysisScope scope = AnalysisScopeReader.instance.makeJavaBinaryAnalysisScope(jarFile, null);
		IClassHierarchy ch = ClassHierarchyFactory.make(scope);

		List<Entrypoint> entryPoints = new ArrayList<>();
		IClass ic = ch.lookupClass(
				TypeReference.findOrCreate(ClassLoaderReference.Application,
						StringStuff.deployment2CanonicalTypeString(entryClass)));
		if (ic != null) {
			for (IMethod m : ic.getDeclaredMethods()) {
				if (m.getSelector().getName().toString().equals("fuzzerTestOneInput")) {
					entryPoints.add(new DefaultEntrypoint(m, ch));
				}
			}
		}

		AnalysisOptions opts = new AnalysisOptions(scope, Util.makeMainEntrypoints(ch));
		System.out.println(opts.getAnalysisScope());
		AnalysisCache cache = new AnalysisCacheImpl();
		CallGraphBuilder<InstanceKey> builder = Util.makeZeroOneContainerCFABuilder(opts, cache, ch);
		CallGraph cg = builder.makeCallGraph(opts, null);
		//System.out.println(cg);

		CGNode root = cg.getFakeRootNode();
		int nodeCount = cg.getNumberOfNodes();

		System.out.println("Root Node: " + root);
		System.out.println("Total node count: " + nodeCount);
		for (int i=0; i<nodeCount; i++) {
			CGNode baseNode = cg.getNode(i);
			IMethod method = baseNode.getMethod();
			System.out.println("Base Node #" + i + ": " + baseNode);
			System.out.println("->Context: " + baseNode.getContext());
			System.out.println("->Method: " + method.getSignature() + ":" + method.getLineNumber(0) + "\n");
			Iterator<CallSiteReference> it = baseNode.iterateCallSites();
			while(it.hasNext()) {
				System.out.println(it.next());
			}
			System.out.println("\n");

			if (baseNode.getIR() != null) {
				Iterator<ISSABasicBlock> it2 = baseNode.getIR().getBlocks() ;
				while(it2.hasNext()) {
					System.out.println(it2.next());
				}
				System.out.println("\n\n\n");
			}
		}
	}
}
