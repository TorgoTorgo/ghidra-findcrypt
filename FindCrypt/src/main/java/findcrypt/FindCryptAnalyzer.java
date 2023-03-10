/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package findcrypt;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;

import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer searches through program bytes to locate cryptographic constants and labels them.
 */
public class FindCryptAnalyzer extends AbstractAnalyzer {
	
	private CryptDatabase database;

	public FindCryptAnalyzer() {
		super("Find Crypt", "Find common cryptographic constants", AnalyzerType.BYTE_ANALYZER);
		this.database = null;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// We're on by default
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		// We can analyze anything with bytes!
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// If the database hasn't yet been opened, we'll open it
		if (this.database == null) {
			try {
				this.database = new CryptDatabase();
				ResourceFile resourceFile = Application.getModuleFile("FindCrypt", "data/database.json");
				Msg.info(this, "Loading FindCrypt signature database from file");

				Reader reader = Files.newBufferedReader(resourceFile.getFile(true).toPath());
				this.database.parse(reader);
			} catch (IOException e) {
				log.appendException(e);
				return false;
			}
		}

		for (CryptSignature signature : database.getSignatures()) {
			monitor.checkCanceled();
			
			// We'll start searching from the top of the newly added address range
			Address search_from = set.getMinAddress();
			
			while (search_from != null) {
				monitor.checkCanceled();
				
				// Starting at min_address, find the next occurrence of the bytes from the signature
				Address found_addr = program.getMemory().findBytes(search_from,
						signature.getBytes(), null, true, monitor);
				
				if (found_addr != null) {
					Msg.info(this, String.format("Labelled %s @ %s - %d bytes", signature.getName(),
							found_addr.toString(), signature.getBytes().length));
					try {
						// Add a symbol
						program.getSymbolTable().createLabel(found_addr, "CRYPT_" + signature.getName(), SourceType.ANALYSIS);
						
						// Add a comment
						program.getListing().setComment(found_addr, 0, String.format("Crypt constant %s - %d bytes",
								signature.getName(), signature.getBytes().length));
						
						// Try to create an array
						ArrayDataType dt = new ArrayDataType(new ByteDataType(), signature.getBytes().length, 1);
						try {
							dt.setName("CRYPT_"+ signature.getName());
						} catch (InvalidNameException e) {
							Msg.error(this, "Failed to name datatype " + "CRYPT_" + signature.getName(), e);
						}
						
						try {
							program.getListing().createData(found_addr, dt);
						} catch (CodeUnitInsertionException e) {
							// We failed to attach the datatype, this is probably due to existing data
							// If that's the case, we probably don't want to overwrite it...
							Msg.warn(this, "Could not apply datatype for crypt constant", e);
						}
						
					} catch (InvalidInputException e) {
						log.appendException(e);
						return false;
					}
					
					// Now we search from the address after
					search_from = found_addr.next();
				} else {
					// We didn't find anything... break
					search_from = null;
				}
			}
		}
		
		return true;
	}
	
	@Override
	public void analysisEnded(Program program) {
		// Drop the database and end the analysis
		this.database = null;
		super.analysisEnded(program);
	}
}
