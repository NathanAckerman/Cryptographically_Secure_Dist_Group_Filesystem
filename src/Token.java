import java.util.List;
import java.util.Formatter;
import java.util.Collections;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * An authentication token that acts as a sign to File Servers that the user is who they say they
 * are, as confirmed by the Group Server. This token should be signed by the Group Server (by
 * encrypting with the Group Server's private key the result of the `toSignatureString` method) so
 * that it can then be passed to File Servers for validation and proof of group membership.
 */
public class Token implements UserToken, java.io.Serializable {

	private static final long serialVersionUID = 913582930946637310L;
	private static final String dateFormatter = "yyyy-MM-dd HH:mm:ss";
	private static final long EXPIRATION_INTERVAL = 60; // minutes
	private final String issuer;
	private final String subject;
	private final List<String> groups;
	private byte[] signature;
	private byte[] recipient;
	private final LocalDateTime expiration;

	/**
	 * Default constructor.
	 */
	public Token(String _issuer, String _subject, List<String> _groups) {
		this.issuer = _issuer;
		this.subject = _subject;
		this.groups = _groups;
		// set expiration values
		this.expiration = LocalDateTime.now().plusMinutes(EXPIRATION_INTERVAL);
	}

	/**
	 * Return a copy of the issuer attribute of this Token.
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * Return a copy of the subject attribute of this Token.
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * Return a copy of the groups attribute of this Token.
	 */
	public List<String> getGroups() {
		return groups;
	}

	/**
	 * Return a copy of the signature attribute of this Token.
	 *
	 * @return The byte array signed by the group server.
	 */
	public byte[] getSignature() {
		return signature;
	}

	/**
	 * Sets the signature value of the token to the specified byte array object.
	 *
	 * @param _signature The signed byte array from the group server.
	 */
	public void setSignature(byte[] _signature) {
		this.signature = _signature;
	}

	/**
	 * Set the recipient attribute to the intended byte array. If this is not a hash of the
	 * recipient File Server's public key, signed by the Group Server, then this token should
	 * become unusable on any File Server. 
	 *
	 * @param _recipient The signed byte array from the group server.
	 */
	public void setRecipient(byte[] _recipient) {
		this.recipient = _recipient;
	}

	/**
	 * Return the recipient attribute of this Token that represents the File Server for which this
	 * token can be used.
	 *
	 * @return The byte array representing the signed hash of the intended File Server's public
	 * key.
	 */
	public byte[] getRecipient() {
		return recipient;
	}

	/**
	 * Return whether or not this token is currently expired.
	 *
	 * @return True if the token is expired, false otherwise.
	 */
	public boolean isExpired() {
		return LocalDateTime.now().isAfter(expiration);
	}

	/**
	 * Deterministically stringify the token such that two equivalent tokens will <i>always</i>
	 * stringify to the same string and prevent a SQL-Injection-like attack on this process by
	 * escaping the double quote (") symbols used for this process so that false membership to a
	 * group cannot be portrayed.
	 *
	 * @return The JSON stringified version of this token.
	 */
	public String toSignatureString() {
		// create stringbuilder object for result
		StringBuilder result = new StringBuilder("\"{");
		// have formatter automatically output to stringbuilder
		Formatter f = new Formatter(result);
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern(dateFormatter);
		
		// format and add in the issuer and subject
		f.format(
			"\"issuer\":\"%s\",\"subject\":\"%s\",\"recipient\":\"%s\",\"expiration\":\"%s\",",
			issuer.replace("\"", "\\\""), subject.replace("\"", "\\\""),
			recipient != null ? toHexString(recipient) : "", expiration.format(dtf)
		);

		// begin build the group list
		result.append("\"groups\":[");
		// Sort alphabetically first to keep them in consistent order (this is before escaping
		// quotes)
		Collections.sort(groups);
		for(String g : groups) {
			f.format("\"%s\",", g.replace("\"", "\\\""));
		}
		// make sure the group list isn't empty first
		if(result.charAt(result.length()-1) != '[') {
			// to be JSON, have to drop the final comma
			result.deleteCharAt(result.length()-1);
		}
		// close the group list construction
		result.append("]");

		// finish building the list
		result.append("}\"");
		// return the result
		return result.toString();
	}

	/**
	 * Standard toString method.
	 *
	 * @return A string in the format `[Token: {subject}]`.
	 */
	public String toString() {
		StringBuilder result = new StringBuilder();
		Formatter f = new Formatter(result);
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern(dateFormatter);
		f.format("[Token: \"%s\" - \"%s\"]", subject, expiration.format(dtf));
		return result.toString();
	}

	/**
	 * Converts a byte array into a hexadecimal string.
	 *
	 * This was heavily inspired by the file found in `beg-crypto-examples.zip` on the bouncy
	 * castle documentation website:
	 * `http://media.wiley.com/product_ancillary/30/07645963/DOWNLOAD/beg_crypto_examples.zip`
	 *
	 * @param a The byte array to convert.
	 * @return A hexadecimal string.
	 */
	public String toHexString(byte[] a) {
		String digits = "0123456789ABCDEF";
		int len = a.length;
		StringBuilder out = new StringBuilder();
		out.append("0x");

		for(int i=0; i < len; i++) {
			int b = a[i] & 0xFF; // isolate the byte
			// convert to index and append
			out.append(digits.charAt(b >> 4)); // shift to isolate first char
			out.append(digits.charAt(b & 0xF)); // & to isolate last char
		}
		return out.toString();
	}
}
