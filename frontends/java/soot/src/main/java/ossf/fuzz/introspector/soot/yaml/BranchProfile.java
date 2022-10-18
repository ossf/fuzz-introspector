package ossf.fuzz.introspector.soot.yaml;

public class BranchProfile {
	private String branchString;
	private BranchSide branchSides;

	public String getBranchString() {
		return branchString;
	}

	public void setBranchString(String branchString) {
		this.branchString = branchString;
	}

	public BranchSide getBranchSides() {
		return branchSides;
	}

	public void setBranchSides(BranchSide branchSides) {
		this.branchSides = branchSides;
	}
}
