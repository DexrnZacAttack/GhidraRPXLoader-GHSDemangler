package cafeloader;

import ghidra.app.plugin.core.analysis.AbstractDemanglerAnalyzer;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

//based off of https://github.com/Cuyler36/Ghidra-GameCube-Loader/blob/master/src/main/java/gamecubeloader/common/CodeWarriorDemangler.java
//and https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/MicrosoftDemangler/src/main/java/ghidra/app/plugin/core/analysis/MicrosoftDemanglerAnalyzer.java

public class GHSDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangle GHS";
	private static final String DESCRIPTION =
			"After a function is created, this analyzer will attempt to demangle " +
					"the name and apply datatypes to parameters." +
					"WARNING: THIS DEMANGLER IS A HUGE HACK AND BASED ON GUESSWORK!!!";
	private static final String OPTION_NAME_APPLY_SIGNATURE = "apply function signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
			"apply decoded function signature alongside basename (a little sketchy, use at your own risk)";

	//private static final String OPTION_NAME_APPLY_ONLY_KNOWN = "apply only known symbol patterns";
	//private static final String OPTION_DESCRIPTION_APPLY_ONLY_KNOWN = "only apply known symbols patterns and exclude any based on guesswork";

	private boolean applyFunctionSignature = false;
	//private boolean applyOnlyKnown = true;

	private final GHSDemangler demangler = new GHSDemangler();

	public GHSDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature, null, OPTION_DESCRIPTION_APPLY_SIGNATURE);
		//options.registerOption(OPTION_NAME_APPLY_ONLY_KNOWN, applyOnlyKnown, null, OPTION_DESCRIPTION_APPLY_ONLY_KNOWN);
	}


	@Override
	public void optionsChanged(Options options, Program program) {
		applyFunctionSignature = options.getBoolean(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature);
		//applyOnlyKnown = options.getBoolean(OPTION_NAME_APPLY_ONLY_KNOWN, applyOnlyKnown);
	}


	@Override
	protected DemangledObject doDemangle(String mangled, DemanglerOptions options, MessageLog log)
			throws DemangledException {
		options.setApplySignature(applyFunctionSignature);
		//options.setDemangleOnlyKnownPatterns(applyOnlyKnown);
		return demangler.demangle(mangled, options);
	}

}
