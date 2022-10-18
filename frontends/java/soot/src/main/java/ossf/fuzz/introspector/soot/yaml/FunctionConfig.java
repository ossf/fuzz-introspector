package ossf.fuzz.introspector.soot.yaml;

import java.util.ArrayList;
import java.util.List;

public class FunctionConfig {
	private String listName;
	private List<FunctionElement> functionElements;

	public FunctionConfig() {
		this.functionElements = new ArrayList<FunctionElement>();
	}

	public String getListName() {
		return listName;
	}

	public void setListName(String listName) {
		this.listName = listName;
	}

	public List<FunctionElement> getFunctionElements() {
		return functionElements;
	}

	public void addFunctionElement(FunctionElement functionElement) {
		this.functionElements.add(functionElement);
	}

	public void setFunctionElements(List<FunctionElement> functionElements) {
		this.functionElements = functionElements;
	}
}
