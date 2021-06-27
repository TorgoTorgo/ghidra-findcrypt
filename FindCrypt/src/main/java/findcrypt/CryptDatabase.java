package findcrypt;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.NotImplementedException;

import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;

/**
 * A simple data structure that deserializes {@link CryptSignature}
 * objects from a file.
 *
 * @author torgo
 */
public class CryptDatabase {
	private final ArrayList<CryptSignature> signatures;

	public CryptDatabase() {
		this.signatures = new ArrayList<>();
	}

	public void parse(Reader reader) {
		Gson gson = new Gson();
		final ArrayList<CryptSignature> loadedSignatures = gson.fromJson(reader, new TypeToken<ArrayList<CryptSignature>>() {
		}.getType());
		loadedSignatures.forEach(signature -> addSignature(signature.getName(), signature.getHexBytes()));
	}
	
	public ArrayList<CryptSignature> getSignatures() {
		return this.signatures;
	}
	
	public void addSignature(String name, String hexString) {
		CryptSignature sig = new CryptSignature(name, hexString);
		this.signatures.add(sig);
		Msg.debug(this, String.format("Added signature: %s", sig.getName()));
	}
}
