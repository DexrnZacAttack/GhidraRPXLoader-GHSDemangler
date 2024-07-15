package cafeloader;

//stolen 99% unchanged from https://github.com/Maschell/ghs-demangle-java/blob/master/src/main/java/de/mas/wiiu/StringWrapper.java

public class StringWrapper {
	private String value;

	public void setValue(String val) {
		this.value = val;
	}

	public String getValue() {
		return value;
	}

	public String toString() {
		return value;
	}

}
