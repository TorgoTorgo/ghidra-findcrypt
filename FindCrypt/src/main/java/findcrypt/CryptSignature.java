/**
 * 
 */
package findcrypt;

/**
 * @author torgo
 *
 */
public class CryptSignature {
	private String name;
	private byte[] data;
	
	public CryptSignature(String name, byte[] data) {
		this.name = name;
		this.data = data;
	}
	
	public byte[] getBytes() {
		return this.data;
	}
	
	public String getName() {
		return this.name;
	}
	
	public void deserialize() {
		
	}
}
