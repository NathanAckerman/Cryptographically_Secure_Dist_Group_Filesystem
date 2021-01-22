
import java.util.List;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken {
	/**
	 * This method should return a string describing the issuer of
	 * this token.  This string identifies the group server that
	 * created this token.  For instance, if "Alice" requests a token
	 * from the group server "Server1", this method will return the
	 * string "Server1".
	 *
	 * @return The issuer of this token
	 *
	 */
	public String getIssuer();


	/**
	 * This method should return a string indicating the name of the
	 * subject of the token.  For instance, if "Alice" requests a
	 * token from the group server "Server1", this method will return
	 * the string "Alice".
	 *
	 * @return The subject of this token
	 *
	 */
	public String getSubject();


	/**
	 * This method extracts the list of groups that the owner of this
	 * token has access to.  If "Alice" is a member of the groups "G1"
	 * and "G2" defined at the group server "Server1", this method
	 * will return ["G1", "G2"].
	 *
	 * @return The list of group memberships encoded in this token
	 *
	 */
	public List<String> getGroups();

	/**
	 * Deterministically stringify the token such that two equivalent tokens will <i>always</i>
	 * stringify to the same string and prevent a SQL-Injection-like attack on this process by
	 * escaping the double quote (") symbols used for this process so that false membership to a
	 * group cannot be portrayed.
	 *
	 * @return The JSON stringified version of this token.
	 */
	public String toSignatureString();

	/**
	 * Return the signature attribute of this Token.
	 *
	 * @return The byte array signed by the group server.
	 */
	public byte[] getSignature();

	/**
	 * Sets the signature value of the token to the specified byte array object.
	 *
	 * @param _signature The signed byte array from the group server.
	 */
	public void setSignature(byte[] _signature);

	/**
	 * Return the recipient attribute of this Token that represents the File Server for which this
	 * token can be used.
	 *
	 * @return The byte array representing the signed hash of the intended File Server's public
	 * key.
	 */
	public byte[] getRecipient();

	/**
	 * Return whether or not this token is currently expired.
	 *
	 * @return True if the token is expired, false otherwise.
	 */
	public boolean isExpired();

	/**
	 * Set the recipient attribute to the intended byte array. If this is not a hash of the
	 * recipient File Server's public key, signed by the Group Server, then this token should
	 * become unusable on any File Server. 
	 *
	 * @param _recipient The signed byte array from the group server.
	 */
	public void setRecipient(byte[] _recipient);

}   //-- end interface UserToken