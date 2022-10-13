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

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.util.Properties;
import java.util.jar.JarFile;

import org.apache.commons.io.FileUtils;

import com.ibm.wala.cast.ir.ssa.AstIRFactory;
import com.ibm.wala.cast.java.client.impl.ZeroOneContainerCFABuilderFactory;
import com.ibm.wala.cast.java.ipa.callgraph.JavaSourceAnalysisScope;
import com.ibm.wala.cast.java.translator.jdt.ecj.ECJClassLoaderFactory;
import com.ibm.wala.core.util.warnings.Warnings;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisOptions.ReflectionOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.CallGraphBuilder;
import com.ibm.wala.ipa.callgraph.CallGraphBuilderCancelException;
import com.ibm.wala.ipa.callgraph.IAnalysisCacheView;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.properties.WalaProperties;
import com.ibm.wala.ssa.SymbolTable;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.util.io.CommandLine;

public class JavaSourceCallGraphGenerator {
	public static void main(String[] args)
			throws IOException, ClassHierarchyException, IllegalArgumentException,CallGraphBuilderCancelException {
		// Handle basic parameter
		Properties p = CommandLine.parse(args);
		String sourceDir = p.getProperty("sourceDir");
		if (sourceDir == null) {
			System.err.println("No sourceDir specified");
			return;
		}

		System.out.println("sourceDir: " + FileSystems.getDefault().getPath(sourceDir).toAbsolutePath());

		// Setup basic analysing scope
		AnalysisScope scope = new JavaSourceAnalysisScope();

		// Add stdlibs of java
		for (String stdlib : WalaProperties.getJ2SEJarFiles()) {
			System.out.println(stdlib);
			scope.addToScope(ClassLoaderReference.Primordial, new JarFile(stdlib));
		}

		// Add target application source
		File root = new File(sourceDir);
		if (root.isDirectory()) {
			for (File file:FileUtils.listFiles(root, new String[] {"class"}, true)) {
				scope.addSourceFileToScope(JavaSourceAnalysisScope.SOURCE, file, file.getName());
			}
		} else {
			System.err.println("Invalid sourceDir specified");
			return;
		}

		// Set class hierarchy and options
		IClassHierarchy ch = ClassHierarchyFactory.make(scope, new ECJClassLoaderFactory(scope.getExclusions()));
		System.out.println(ch.getNumberOfClasses() + " classes");
		System.out.println(Warnings.asString());
		Warnings.clear();

		AnalysisOptions opts = new AnalysisOptions();
		opts.setEntrypoints(Util.makeMainEntrypoints(JavaSourceAnalysisScope.SOURCE, ch, new String[] {"LTestFuzzer"}));
		opts.getSSAOptions().setDefaultValues(SymbolTable::getDefaultValue);
		opts.setReflectionOptions(ReflectionOptions.NONE);

		// Build up Call Graph
		IAnalysisCacheView cache =
				new AnalysisCacheImpl(AstIRFactory.makeDefaultFactory(), opts.getSSAOptions());
		CallGraphBuilder<?> builder = new ZeroOneContainerCFABuilderFactory().make(opts, cache, ch);
		System.out.println("building call graph...");
		CallGraph cg = builder.makeCallGraph(opts, null);
		System.out.println(cg);

//		// Print call graph data for verification (or further processing)
//		for (int i=0; i<cg.getNumberOfNodes(); i++) {
//			CGNode baseNode = cg.getNode(i);
//			IMethod method = baseNode.getMethod();
//			System.out.println("Base Node #" + i + ": " + baseNode);
//			System.out.println("->Context: " + baseNode.getContext());
//			System.out.println("->Method: " + method.getSignature() + ":" + method.getLineNumber(0) + "\n");
//			Iterator<CallSiteReference> it = baseNode.iterateCallSites();
//			while(it.hasNext()) {
//				System.out.println(it.next());
//			}
//			System.out.println("\n");
//
//			if (baseNode.getIR() != null) {
//				Iterator<ISSABasicBlock> it2 = baseNode.getIR().getBlocks() ;
//				while(it2.hasNext()) {
//					System.out.println(it2.next());
//				}
//				System.out.println("\n\n\n");
//			}
//		}
//
//		System.out.println(CallGraphStats.getStats(cg));
	}
}
