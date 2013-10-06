package uk.org.tomek.encryptme.helpers;

public final class HexStringHelper {
	
	/**
     * Hex encodes a byte array. <BR>
     * Returns an empty string if the input array is null or empty. <p>
     * From http://www.scottjjohnson.com/blog/AesWithCbcExample.java
     * 
     * @param input bytes to encode
     * @return string containing hex representation of input byte array
     */
	public static String hexEncode(byte[] input) {
		if (input == null || input.length == 0) {
			return "";
		}

		int inputLength = input.length;
		StringBuilder output = new StringBuilder(inputLength * 2);

		for (int i = 0; i < inputLength; i++) {
			int next = input[i] & 0xff;
			if (next < 0x10) {
				output.append("0");
			}

			output.append("0x");
			output.append(Integer.toHexString(next));
			output.append(", ");
		}

		return output.toString();
	}

}
