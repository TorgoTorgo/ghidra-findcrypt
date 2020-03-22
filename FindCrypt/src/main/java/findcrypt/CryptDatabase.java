/**
 * 
 */
package findcrypt;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

import org.apache.commons.lang3.NotImplementedException;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * @author torgo
 *
 */
public class CryptDatabase {
	private ArrayList<CryptSignature> signatures;
	private MessageLog log;
	
	public CryptDatabase(MessageLog log) {
		this.signatures = new ArrayList<CryptSignature>();
		this.log = log;
	}
	
	public void parse(InputStream stream) throws IOException {
		// Parse out sigs
		byte[] _buff = stream.readAllBytes();
		ByteBuffer buff = ByteBuffer.wrap(_buff);
		buff.order(ByteOrder.BIG_ENDIAN);
		byte[] expected_magic = {(byte) 0xd3, 0x01, 0x04, 0x01};
		byte magic[] = new byte[4];
		
		buff.get(magic, 0, 4);
		
		for (int i = 0; i < 4; i++) {
			if (expected_magic[i] != magic[i]) {
				log.appendMsg("Failed to load, invalid magic!");
				throw new IOException(String.format("Bad database file magic: 0x%02X%02X%02X%02X",
						magic[0], magic[1], magic[2], magic[3]));
			}
		}
		
		
		// Magic is correct
		short total_entries = buff.getShort();
		Msg.info(this, String.format("Loading %d signatures", total_entries));
		for (int i = 0; i < total_entries; i++) {
			int name_size = buff.getInt();
			byte name_buff[] = new byte[name_size];
			buff.get(name_buff, 0, name_size);
			byte compressed = buff.get();
			if (compressed == 0x1) {
				// This is a gzipped entry
				NotImplementedException e =
						new NotImplementedException("We don't implement compressed entries!");
				log.appendException(e);
				throw e;
			}
			int data_size = buff.getInt();
			byte data[] = new byte[data_size];
			buff.get(data, 0, data_size);
			this.addSignature(new String(name_buff), data);	
		}
		
	}
	
	public ArrayList<CryptSignature> getSignatures() {
		return this.signatures;
	}
	
	public void addSignature(String name, byte[] data) {
		CryptSignature sig = new CryptSignature(name, data);
		this.signatures.add(sig);
		Msg.debug(this, String.format("Added signature: %s", sig.getName()));

	}
}
