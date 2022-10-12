package ossf.fuzz.introspector.wala;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.util.Iterator;
import java.util.Properties;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.ipa.callgraph.AnalysisCache;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.CallGraphBuilder;
import com.ibm.wala.ipa.callgraph.CallGraphBuilderCancelException;
import com.ibm.wala.ipa.callgraph.CallGraphStats;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.ISSABasicBlock;
import com.ibm.wala.util.io.CommandLine;

public class JarCallGraphGenerator {
	public static void main(String[] args) throws IOException, ClassHierarchyException, IllegalArgumentException,
	CallGraphBuilderCancelException {
		// Handle basic parameter
		Properties p = CommandLine.parse(args);
		String jarFile = p.getProperty("jarFile");
		String entryClass = p.getProperty("entryClass");
		if (jarFile == null || entryClass == null) {
			return;
		}

		System.out.println("jarFile: " + FileSystems.getDefault().getPath(jarFile).toAbsolutePath());
		System.out.println("entryClass: " + entryClass);

		// Setup basic analysing scope
		AnalysisScope scope = AnalysisScopeReader.instance.readJavaScope("cg.scope", null, ClassLoader.getSystemClassLoader());
		IClassHierarchy ch = ClassHierarchyFactory.make(scope);

		//TODO: Attempt to search for target method as entry point, still have some bugs to solve
//		List<Entrypoint> entryPoints = new ArrayList<Entrypoint>();
//		IClass klass = ch.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Application,
//		        StringStuff.deployment2CanonicalTypeString(entryClass)));
//				for (IMethod method : klass.getDeclaredMethods()) {
//				     System.out.println(method);
//		}

		// Build up Call Graph
		AnalysisOptions opts = new AnalysisOptions(scope, Util.makeMainEntrypoints(ch));
		System.out.println(opts.getAnalysisScope());

		AnalysisCache cache = new AnalysisCacheImpl();
		CallGraphBuilder<InstanceKey> builder = Util.makeZeroOneContainerCFABuilder(opts, cache, ch);
		CallGraph cg = builder.makeCallGraph(opts, null);
		//System.out.println(cg);

		// Print call graph data for verification (or further processing)
		for (int i=0; i<cg.getNumberOfNodes(); i++) {
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
		System.out.println(CallGraphStats.getStats(cg));
	}
}
