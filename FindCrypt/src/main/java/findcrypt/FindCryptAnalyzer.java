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

import java.io.FileNotFoundException;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.CommentTypes;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.CommentType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class FindCryptAnalyzer extends AbstractAnalyzer {
	
	private CryptDatabase database;

	public FindCryptAnalyzer() throws FileNotFoundException {

		// TODO: Name the analyzer and give it a description.
		super("Find Crypt", "Find common crypt constants", AnalyzerType.BYTE_ANALYZER);
		this.database = null;

	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		if (this.database == null) {
			try {
				this.database = new CryptDatabase(log);
				ResourceFile file = Application.getModuleFile("FindCrypt", "data/database.d3v");
				Msg.info(this, "Loading FindCrypt signature database from file");
				this.database.parse(file.getInputStream());
			} catch (FileNotFoundException e) {
				log.appendException(e);
				return false;
			} catch (IOException e) {
				log.appendException(e);
				return false;
			}
		}

		for (CryptSignature signature : database.getSignatures()) {
			monitor.checkCanceled();
			Address found_addr = program.getMemory().findBytes(set.getMinAddress(),
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
					ArrayDataType dt = new ArrayDataType(ByteDataType.DEFAULT, signature.getBytes().length, 1);
					try {
						dt.setName("CRYPT_"+ signature.getName());
					} catch (InvalidNameException e) {
						Msg.error(this, "Failed to name datatype " + "CRYPT_" + signature.getName(), e);
					}
					
					try {
						program.getListing().createData(found_addr, dt);
					} catch (CodeUnitInsertionException | DataTypeConflictException e) {
						// We failed to attach the datatype, this is probably due to existing data
						// If that's the case, we probably don't want to overwrite it...
						Msg.warn(this, "Could not apply datatype for crypt constant", e);
					}
					
				} catch (InvalidInputException e) {
					log.appendException(e);
					return false;
				}
			}
		}
		return true;
	}
	
	@Override
	public void analysisEnded(Program program) {
		this.database = null;
		super.analysisEnded(program);
	}
}
