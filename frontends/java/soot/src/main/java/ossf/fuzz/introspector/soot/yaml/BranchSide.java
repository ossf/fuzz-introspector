package ossf.fuzz.introspector.soot.yaml;

import java.util.ArrayList;
import java.util.List;

public class BranchSide {
	private String trueSides;
	private List<String> trueSidesFuncs;
	private String falseSides;
	private List<String> falseSidesFuncs;

	public BranchSide() {
		this.trueSidesFuncs = new ArrayList<String>();
		this.falseSidesFuncs = new ArrayList<String>();
	}

	public String getTrueSides() {
		return trueSides;
	}

	public void setTrueSides(String trueSides) {
		this.trueSides = trueSides;
	}

	public List<String> getTrueSidesFuncs() {
		return trueSidesFuncs;
	}

	public void addTrueSidesFuncs(String trueSidesFunc) {
		this.trueSidesFuncs.add(trueSidesFunc);
	}

	public void setTrueSidesFuncs(List<String> trueSidesFuncs) {
		this.trueSidesFuncs = trueSidesFuncs;
	}

	public String getFalseSides() {
		return falseSides;
	}

	public void setFalseSides(String falseSides) {
		this.falseSides = falseSides;
	}

	public List<String> getFalseSidesFuncs() {
		return falseSidesFuncs;
	}

	public void addFalseSidesFuncs(String falseSidesFunc) {
		this.falseSidesFuncs.add(falseSidesFunc);
	}

	public void setFalseSidesFuncs(List<String> falseSidesFuncs) {
		this.falseSidesFuncs = falseSidesFuncs;
	}
}
