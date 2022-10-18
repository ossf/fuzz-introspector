package ossf.fuzz.introspector.soot.yaml;

public class FuzzerConfig {
	private String filename;
	private FunctionConfig functionConfig;

	public String getFilename() {
		return filename;
	}

	public void setFilename(String filename) {
		this.filename = filename;
	}

	public FunctionConfig getFunctionConfig() {
		return functionConfig;
	}

	public void setFunctionConfig(FunctionConfig functionConfig) {
		this.functionConfig = functionConfig;
	}
}
