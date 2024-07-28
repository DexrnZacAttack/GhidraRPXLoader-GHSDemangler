package cafeloader;

//plagiarized from https://github.com/Maschell/ghs-demangle-java/blob/master/src/main/java/de/mas/wiiu/App.java
//additional code stolen from https://github.com/Cuyler36/Ghidra-GameCube-Loader/blob/master/src/main/java/gamecubeloader/common/CodeWarriorDemangler.java

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.DemanglerParseException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.util.Map.entry;

//damn
//he really didn't lie about it being an ugly port

//TODO: Ghidra-ify more
public final class GHSDemangler implements Demangler {
	private static List<DemangledDataType> arguments;
	private static boolean isThunk;

	private static final String[] templatePrefixes = new String[] { "tm", "ps", "pt" /* XXX from libiberty cplus-dem.c */ };
	private static final Map<String, String> baseNames = Map.ofEntries( //TODO: turn this into ghidra-ified DemangledDataType.blah stuff
		entry("__vtbl", " virtual table"),
		entry("__ct", "#"),
		entry("__dt", "~#"),
		entry("__as", "operator="),
		entry("__eq", "operator=="),
		entry("__ne", "operator!="),
		entry("__gt", "operator>"),
		entry("__lt", "operator<"),
		entry("__ge", "operator>="),
		entry("__le", "operator<="),
		entry("__pp", "operator++"),
		entry("__pl", "operator+"),
		entry("__apl", "operator+="),
		entry("__mi", "operator-"),
		entry("__ami", "operator-="),
		entry("__ml", "operator*"),
		entry("__amu", "operator*="),
		entry("__dv", "operator/"),
		/* XXX below baseNames have not been seen - guess from libiberty cplus-dem.c */
		entry("__adv", "operator/="),
		entry("__nw", "operator.new"), //TODO: these 4 are modified, the rest is janky
		entry("__dl", "operator.delete"),
		entry("__vn", "operator.new[]"),
		entry("__vd", "operator.delete[]"),
		entry("__md", "operator%"),
		entry("__amd", "operator%="),
		entry("__mm", "operator--"),
		entry("__aa", "operator&&"),
		entry("__oo", "operator||"),
		entry("__or", "operator|"),
		entry("__aor", "operator|="),
		entry("__er", "operator^"),
		entry("__aer", "operator^="),
		entry("__ad", "operator&"),
		entry("__aad", "operator&="),
		entry("__co", "operator~"),
		entry("__cl", "operator()"),
		entry("__ls", "operator<<"),
		entry("__als", "operator<<="),
		entry("__rs", "operator>>"),
		entry("__ars", "operator>>="),
		entry("__rf", "operator->"),
		entry("__vc", "operator[]")
	);
	private final static Map<Character, String> baseTypes = Map.ofEntries(
		entry('v', DemangledDataType.VOID),
		entry('i', DemangledDataType.INT),
		entry('s', DemangledDataType.SHORT),
		entry('c', DemangledDataType.CHAR),
		entry('w', DemangledDataType.WCHAR_T),
		entry('b', DemangledDataType.BOOL),
		entry('f', DemangledDataType.FLOAT),
		entry('d', DemangledDataType.DOUBLE),
		entry('l', DemangledDataType.LONG),
		entry('L', DemangledDataType.LONG_LONG),
		entry('e', DemangledDataType.VARARGS),
		/* XXX below baseTypes have not been seen - guess from libiberty cplus-dem.c */
		entry('r', DemangledDataType.LONG_DOUBLE)
	);
	private final static Map<Character, String> typePrefixes = Map.ofEntries(
		entry('U', DemangledDataType.UNSIGNED),
		entry('S', DemangledDataType.SIGNED),
		/* XXX below typePrefixes have not been seen - guess from libiberty cplus-dem.c */
		entry('J', DemangledDataType.COMPLEX)
	);
	private final static Map<Character, String> typeSuffixes = Map.ofEntries(
		entry('P', DemangledDataType.PTR_NOTATION),
		entry('R', DemangledDataType.REF_NOTATION),
		entry('C', DemangledDataType.CONST),
		entry('V', DemangledDataType.VOLATILE), /* XXX this is a guess! */
		/* XXX below typeSuffixes have not been seen - guess from libiberty cplus-dem.c */
		entry('u', DemangledDataType.RESTRICT)
	);

	private static int ReadInt(String name, StringWrapper nameWrapper) {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Unexpected end of string. Expected a digit.");
		}
		if (!Character.isDigit(name.charAt(0))) {
			throw new IllegalArgumentException("Unexpected character \"" + name.charAt(0) + "\". Expected a digit.");
		}

		int i = 1;
		while (i < name.length() && Character.isDigit(name.charAt(i))) {
			i++;
		}

		nameWrapper.setValue(name.substring(i));

		return Integer.parseInt(name.substring(0, i));
	}

	private static String Decompress(String name) {
		if (!name.startsWith("__CPR")) return name;

		name = name.substring(5);

		StringWrapper outWrap = new StringWrapper();
		int decompressedLen = ReadInt(name, outWrap);
		name = outWrap.getValue();

		if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected compressed symbol name.");
		if (!name.startsWith("__"))
			throw new IllegalArgumentException("Unexpected character(s) after compression len: \"" + name.charAt(0) + "\". Expected \"__\".");
		name = name.substring(2);

		String result = "";
		int index = 0;

		/* find all instances of J<num>J */
		while (true) {
			int start = name.indexOf('J', index);

			if (start != -1) {
				result += name.substring(index, index + start - index);

				int end = name.indexOf('J', start + 1);

				if (end != -1) {
					boolean valid = true;

					/* check all characters between Js are digits */
					for (int i = start + 1; i < end; i++)
						if (!Character.isDigit(name.charAt(i))) {
							valid = false;
							break;
						}

					if (end < start) valid = false;

					if (valid) {

						int loc = Integer.parseInt(name.substring(start + 1, start + 1 + end - start - 1));

						String tmp;
						StringWrapper tmpWrap = new StringWrapper();
						int len = ReadInt(result.substring(loc), tmpWrap);
						tmp = tmpWrap.getValue();

						if (len == 0 || len > tmp.length()) throw new IllegalArgumentException("(DECOMPRESS) Bad string length \"" + len + "\".");

						result += len + tmp.substring(0, len);
						index = end + 1;
					} else {
						result += name.substring(start, start + 1);
						index = start + 1;
					}
				} else {
					result += name.substring(start, start + 1);
					index = start + 1;
				}
			} else {
				result += name.substring(index);
				break;
			}
		}

		if (result.length() != decompressedLen) {
			throw new IllegalArgumentException("Bad decompression length length \"" + decompressedLen + "\". Expected \"" + result.length() + "\".");
		}

		return result;
	}

	private static String ReadNameSpace(String name, StringWrapper remainder) {
		if (name == null || name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"Q\".");
		if (!name.startsWith("Q")) throw new IllegalArgumentException("Unexpected character \"" + name.charAt(0) + "\". Expected \"Q\".");

		StringWrapper outWrap = new StringWrapper();
		int count = ReadInt(name.substring(1), outWrap);
		name = outWrap.getValue();

		if (count == 0) throw new IllegalArgumentException("Bad namespace count \"" + count + "\".");
		if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
		if (!name.startsWith("_")) throw new IllegalArgumentException("Unexpected character after namespace count \"" + name.charAt(0) + "\". Expected \"_\".");

		remainder.setValue(name.substring(1));

		String result = "";
		for (int j = 0; j < count; j++) {
			String current;
			if (remainder.getValue().startsWith("Z")) {
				int end = remainder.getValue().indexOf("Z", 1);

				if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

				current = remainder.getValue().substring(0, end);
				remainder.setValue(name.substring(end + 2));
			} else {
				current = ReadString(remainder.getValue(), remainder);
			}

			result += (!result.isEmpty() ? "::" : "") + current;
		}

		return result;
	}

	private static String ReadArguments(String name, StringWrapper remainder) {
		String result = "";
		List<String> args = new ArrayList<>(); //TODO: i think we might be able to get rid of this?

		remainder.setValue(name);

		while (!remainder.getValue().isEmpty() && !remainder.getValue().startsWith("_")) {
			if (!args.isEmpty()) result += ", ";

			String t = ReadType(args, remainder.getValue(), remainder);
			result += t.replace("#", "");
			if(t.equals("...#")) {
				if( arguments.isEmpty() ) {
					throw new DemanglerParseException("Demangler outputted varargs before any type was defined!");
				}
				arguments.get(arguments.size() - 1).setVarArgs();
			} else
				arguments.add( new DemangledDataType( null, null, t.replace("#", "") ) );

			//TODO: the return value is redundant now.

			args.add(t);
		}

		return result;
	}

	private static String ReadType(List<String> args, String name, StringWrapper remainder) {
		if (name == null || name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected a type.");

		/* e.g. "i" => "int#" */
		if (baseTypes.containsKey(name.charAt(0))) {
			remainder.setValue(name.substring(1));
			return baseTypes.get(name.charAt(0)) + "#";
		}
		/* e.g. "Q2_3std4move__tm__2_w" => "std::move<wchar_t>#" */
		else if (name.startsWith("Q"))
			return ReadNameSpace(name, remainder) + "#";
			/* e.g. "8MyStruct" => "MyStruct#" */
		else if (Character.isDigit(name.charAt(0)))
			return ReadString(name, remainder) + "#";
			/* e.g. "ui" => "unsigned int#" */
		else if (typePrefixes.containsKey(name.charAt(0)))
			return typePrefixes.get(name.charAt(0)) + " " + ReadType(args, name.substring(1), remainder);
			/* e.g. "Pv" => "void *#" */
		else if (typeSuffixes.containsKey(name.charAt(0)))
			return ReadType(args, name.substring(1), remainder).replace("#", " " + typeSuffixes.get(name.charAt(0)) + "#");
			/* e.g. "Z1Z" => "Z1#" */
		else if (name.startsWith("Z")) {
			int end = name.indexOf("Z", 1);
			if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

			remainder.setValue(name.substring(end + 1));
			return name.substring(0, end) + "#";
		}
		/* e.g. "A2_i" => "int#[2]" */
		else if (name.startsWith("A")) {
			String len;

			name = name.substring(1);

			if (name.startsWith("_Z")) {
				int end = name.indexOf("Z", 2);

				if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

				len = name.substring(1, 1 + end - 1);
				name = name.substring(end + 1);
			} else {
				StringWrapper nameWrapper = new StringWrapper();
				len = Integer.toString(ReadInt(name, nameWrapper));
				name = nameWrapper.getValue();
			}

			if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!name.startsWith("_"))
				throw new IllegalArgumentException("Unexpected character after array length \"" + name.charAt(0) + "\". Expected \"_\".");

			return ReadType(args, name.substring(1), remainder).replace("#", "#[" + len + "]");
		}
		/* e.g. "FPv_v" => "void (#)(void *)" */
		else if (name.startsWith("F")) {
			StringWrapper nameWrapper = new StringWrapper();
			String declArgs = ReadArguments(name.substring(1), nameWrapper);
			name = nameWrapper.getValue();

			/* XXX bit of a hack - we're allowed not to have a return type on top level methods, which we detected by the args argument being null. */

			boolean parseable = false;
			try {
				if (!name.isEmpty()) {
					Integer.parseInt(name.substring(1));
					parseable = true;
				}
			} catch (NumberFormatException e) {
				parseable = false;
			}
			if (args == null) {
				if (name.isEmpty() || (name.startsWith("_") && parseable)) {
					remainder.setValue(name);
					return "#(" + declArgs + ")";
				}

			}

			if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!name.startsWith("_"))
				throw new IllegalArgumentException("Unexpected character after argument declaration \"" + name.charAt(0) + "\". Expected \"_\".");

			return ReadType(args, name.substring(1), remainder).replace("#", "(#)(" + declArgs + ")");
		}
		/* T<a> expands to argument <a> */
		else if (name.startsWith("T")) {
			if (name.length() < 2) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!Character.isDigit(name.charAt(1))) throw new IllegalArgumentException("Unexpected character \"" + name.charAt(1) + "\". Expected a digit.");

			int arg = Integer.parseInt(name.substring(1, 2));

			remainder.setValue(name.substring(2));

			if (args.size() < arg) throw new IllegalArgumentException("Bad argument number \"" + arg + "\".");

			return args.get(arg - 1);
		}
		/* N<c><a> expands to <c> repetitions of argument <a> */
		else if (name.startsWith("N")) {
			if (name.length() < 3) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!Character.isDigit(name.charAt(1)) || !Character.isDigit(name.charAt(2)))
				throw new IllegalArgumentException("Unexpected character(s) \"" + name.charAt(1) + name.charAt(2) + "\". Expected two digits.");

			int count = Integer.parseInt(name.substring(1, 2));
			int arg = Integer.parseInt(name.substring(2, 3));

			if (count > 1)
				remainder.setValue("N" + (count - 1) + arg + name.substring(3));
			else
				remainder.setValue(name.substring(3));

			if (args.size() < arg) throw new IllegalArgumentException("Bad argument number \"" + arg + "\".");

			return args.get(arg - 1);
		} else
			throw new IllegalArgumentException("Unknown type: \"" + name.charAt(0) + "\".");
	}

	private static String ReadString(String name, StringWrapper remainder) {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Unexpected end of string. Expected a digit.");
		}

		StringWrapper nameWrapper = new StringWrapper();
		int len = ReadInt(name, nameWrapper);
		name = nameWrapper.getValue();
		if (len == 0 || name.length() < len) throw new IllegalArgumentException("(READ STRING) Bad string length \"" + len + "\".");

		remainder.setValue(name.substring(len));
		return DemangleTemplate(name.substring(0, len));
	}

	private static String ReadTemplateArguments(String name, StringWrapper remainder) {
		String result = "";
		List<String> args = new ArrayList<>();

		remainder.setValue(name);

		while (!remainder.getValue().isEmpty() && !remainder.getValue().startsWith("_")) {
			if (!args.isEmpty()) result += ", ";

			String type, val;

			if (remainder.getValue().startsWith("X")) {
				/* X arguments represent named values */

				remainder.setValue(remainder.getValue().substring(1));
				if (remainder.getValue().isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected a type.");

				if (Character.isDigit(remainder.getValue().charAt(0))) {
					/* arbitrary string */
					type = "#";

					val = ReadString(remainder.getValue(), remainder);
				} else {
					/* <type><encoding> */
					type = ReadType(args, remainder.getValue(), remainder).replace("#", " #");

					if (remainder.getValue().startsWith("L")) {
						/* _<len>_<val> */
						remainder.setValue(remainder.getValue().substring(1));
						if (remainder.getValue().isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
						if (!remainder.getValue().startsWith("_")) throw new IllegalArgumentException(
								"Unexpected character after template parameter encoding \"" + remainder.getValue().charAt(0) + "\". Expected \"_\".");

						int len = ReadInt(remainder.getValue().substring(1), remainder);

						if (len == 0 || len > remainder.getValue().length() + 1)
							throw new IllegalArgumentException("Bad template parameter length: \"" + len + "\".");
						if (!remainder.getValue().startsWith("_")) throw new IllegalArgumentException(
								"Unexpected character after template parameter length \"" + remainder.getValue().charAt(0) + "\". Expected \"_\".");

						remainder.setValue(remainder.getValue().substring(1));
						val = remainder.getValue().substring(0, len);
						remainder.setValue(remainder.getValue().substring(len));
					} else
						throw new IllegalArgumentException("Unknown template parameter encoding: \"" + remainder.getValue().charAt(0) + "\".");
				}
			} else {
				val = ReadType(args, remainder.getValue(), remainder).replace("#", "");
				type = "class #";
			}

			/* TODO - the Z notation is ugly - we should resolve args? */
			result += type.replace("#", "Z" + (args.size() + 1) + " = " + val);
			args.add(val);
		}

		return result;
	}

	static boolean StartsWithAny(String str, String[] names) {
		for (String s : names)
			if (str.startsWith(s)) return true;
		return false;
	}

	private static String DemangleTemplate(String name) {
		int mstart;

		mstart = name.indexOf("__", 1);

		/* check for something like "h___tm_2_i" => "h_<int>" */
		if (mstart != -1 && name.substring(mstart).startsWith("___")) mstart++;

		/* not a special symbol name! */
		if (mstart == -1) return name;

		/* something more interesting! */
		String remainder = name.substring(mstart + 2);
		name = name.substring(0, mstart);

		while (true) {
			if (!StartsWithAny(remainder, templatePrefixes)) {
				// throw new IllegalArgumentException("Unexpected template argument prefix. " + remainder);
				return name;

			}

			/* format of remainder should be <type>__<len>_<arg> */
			int lstart = remainder.indexOf("__");

			if (lstart == -1) throw new IllegalArgumentException("Bad template argument: \"" + remainder + "\".");

			remainder = remainder.substring(lstart + 2);

			StringWrapper wrapout = new StringWrapper();

			int len = ReadInt(remainder, wrapout);
			remainder = wrapout.getValue();

			if (len == 0 || len > remainder.length()) throw new IllegalArgumentException("Bad template argument length: \"" + len + "\".");
			if (!remainder.startsWith("_"))
				throw new IllegalArgumentException("Unexpected character after template argument length \"" + remainder.charAt(0) + "\". Expected \"_\".");

			String tmp;
			StringWrapper tmpWrap = new StringWrapper();
			String declArgs = ReadTemplateArguments(remainder.substring(1), tmpWrap);
			tmp = tmpWrap.getValue();

			/* avoid emitting the ">>" token */
			if (declArgs.endsWith(">")) declArgs += " ";

			name += "<" + declArgs + ">";
			remainder = remainder.substring(len);

			if (!tmp.contentEquals(remainder)) throw new IllegalArgumentException("Bad template argument length: \"" + len + "\".");

			/* check if we've hit the end */
			if (remainder.isEmpty()) return name;

			/* should be immediately followed with __ */
			if (!remainder.startsWith("__"))
				throw new IllegalArgumentException("Unexpected character(s) after template: \"" + remainder.charAt(0) + "\". Expected \"__\".");
			remainder = remainder.substring(2);
		}
	}

	private static String ReadBaseName(String name, StringWrapper remainder) {
		String opName;
		int mstart;

		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Unexpected end of string. Expected a name.");
		}

		if (name.startsWith("__op")) {
			StringWrapper stringOut = new StringWrapper();
			/* a cast operator */
			String type = ReadType(null, name.substring(4), stringOut).replace("#", "");
			name = stringOut.getValue();
			opName = "operator " + type;
			name = "#" + name;
		} else {
			opName = "";
		}

		mstart = name.indexOf("__", 1);

		/* check for something like "h___Fi" => "h_" */
		if (mstart != -1 && name.substring(mstart).startsWith("___")) mstart++;

		/* not a special symbol name! */
		if (mstart == -1) {
			remainder.setValue("");
			return name;
		}

		/* something more interesting! */
		remainder.setValue(name.substring(mstart + 2));
		name = name.substring(0, mstart);

		/* check for "__ct__7MyClass" */
		if (baseNames.containsKey(name))
			name = baseNames.get(name);
		else if (name.equals("#")) name = opName;

		while (StartsWithAny(remainder.getValue(), templatePrefixes)) {
			/* format of remainder should be <type>__<len>_<arg> */
			int lstart = remainder.getValue().indexOf("__");

			if (lstart == -1) throw new IllegalArgumentException("Bad template argument: \"" + remainder + "\".");

			/* shift across the template type */
			name += "__" + remainder.getValue().substring(0, lstart);
			remainder.setValue(remainder.getValue().substring(lstart + 2));

			int len = ReadInt(remainder.getValue(), remainder);

			if (len == 0 || len > remainder.getValue().length()) throw new IllegalArgumentException("Bad template argument length: \"" + len + "\".");

			/* shift across the len and arg */
			name += "__" + len + remainder.getValue().substring(0, len);
			remainder.setValue(remainder.getValue().substring(len));

			/* check if we've hit the end */
			if (remainder.getValue().isEmpty()) return name;

			/* should be immediately followed with __ */
			if (!remainder.getValue().startsWith("__"))
				throw new IllegalArgumentException("Unexpected character(s) after template: \"" + remainder.getValue().charAt(0) + "\". Expected \"__\".");
			remainder.setValue(remainder.getValue().substring(2));
		}

		return DemangleTemplate(name);
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions options) { //TODO: get rid of StringWrapper
		if ( !options.demangleOnlyKnownPatterns() && mangled.matches("^__ghs_thunk__0x[a-f 0-9]{8}__.*") ) { //regex here matches the memory address, if you are wondering
			//Msg.warn(GHSDemangler.class, "__ghs_thunk__ pattern is based on uneducated guesswork!!");
			mangled = mangled.substring(25);
			isThunk = true;
		}

		if (mangled.startsWith("__sti__")) {
			throw new DemanglerParseException("\"__sti__\" pattern is unknown."); //TODO: terrible message
		}

		String result;
		arguments = new ArrayList<>();
		mangled = Decompress(mangled);

		/*
		 * This demangle method has basically turned into a hand-written LL(1) recursive descent parser.
		 */

		StringWrapper mangle = new StringWrapper();
		String baseName = ReadBaseName(mangled, mangle);

		/* TODO this may not be right - see S below Q */
		/* h__S__Q1_3clsFi => static cls::h(int) */
		boolean isStatic = false;

		if (mangle.getValue().startsWith("S__")) {
			isStatic = true;
			mangle.setValue(mangle.getValue().substring(3));
		}
		String declNameSpace, declClass;
		if (mangle.getValue().startsWith("Q")) {
			declNameSpace = ReadNameSpace(mangle.getValue(), mangle);

			int last = declNameSpace.lastIndexOf("::");
			if (last != -1)
				declClass = declNameSpace.substring(last + 2);
			else
				declClass = declNameSpace;

			declNameSpace += "::";
		} else if (!mangle.getValue().isEmpty() && Character.isDigit(mangle.getValue().charAt(0))) {
			declClass = ReadString(mangle.getValue(), mangle);
			declNameSpace = declClass + "::";
		} else {
			declNameSpace = "";
			declClass = "";
		}

		baseName = baseName.replace("#", declClass);

		/* static */
		if (mangle.getValue().startsWith("S")) {
			isStatic = true;
			mangle.setValue(mangle.getValue().substring(1));
		}

		boolean isConst = false;
		if (mangle.getValue().startsWith("C")) {
			isConst = true;
			mangle.setValue(mangle.getValue().substring(1));
		}

		String declType;
		if (mangle.getValue().startsWith("F"))
			declType = ReadType(null, mangle.getValue(), mangle); //TODO: return is redundant
		else
			declType = "#";

		/* XXX bit of a hack - some names I see seem to end with _<number> */
		int end;
		if (mangle.getValue().startsWith("_")) {
			end = Integer.parseInt(mangle.getValue().substring(1));

			baseName += "_" + end;
			mangle.setValue("");
		}

		if (!mangle.getValue().isEmpty())
			throw new IllegalArgumentException("Unknown modifier: \"" + mangle.getValue().charAt(0) + "\".");

		result = ((isStatic ? "static " : "") + declType.replace("(#)", " " + declNameSpace + baseName).replace("#", declNameSpace + baseName) + (isConst ? " const" : "") )
				.replace("::" + baseNames.get("__vtbl"), baseNames.get("__vtbl")); //TODO: no


		if(baseName.startsWith("::")) { //TODO: this shouldn't be necessary
			baseName = baseName.substring(2);
		}

		DemangledFunction demangled = new DemangledFunction(mangled, result, baseName);

		if(declNameSpace.endsWith("::")) { //TODO: this neither
			declNameSpace = declNameSpace.substring(0, declNameSpace.length() - 2);
		}

		if(!declNameSpace.isEmpty())
			demangled.setNamespace( new DemangledType(null, declNameSpace, declNameSpace) );

		demangled.setStatic(isStatic);

		if(options.applyCallingConvention())
			demangled.setCallingConvention( !declClass.isEmpty() ? "__thiscall" : "__stdcall" ); //TODO: what does this mean
		//TODO: surely there is some DemangledFunction.THISCALL constant from ghidra that we can use here

		if(baseName.contains("::") && !baseName.contains("<class Z1 = "))
			Msg.warn(GHSDemangler.class, result + " contains :: in basename (" + baseName + ')');


		if(options.applySignature()) {
			for (DemangledDataType type : arguments) //lol, lmao
				demangled.addParameter(type);
		}
		demangled.setThunk(isThunk);
		return demangled;
	}
	@Override
	@SuppressWarnings("removal") //TODO: is this ok?
	public DemangledObject demangle(String mangled, boolean canDemangle) throws DemangledException {
		return demangle(mangled);
	}

	@Override
	public boolean canDemangle(Program program) {
		return (program.getLanguageID().getIdAsString().equals("PowerPC:BE:32:Gekko_Broadway_Espresso"));
	}

	@Override
	public DemanglerOptions createDefaultOptions() {
		return Demangler.super.createDefaultOptions();
	}
}