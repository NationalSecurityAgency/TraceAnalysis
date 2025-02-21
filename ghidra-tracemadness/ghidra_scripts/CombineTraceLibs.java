//Combine all libraries discovered during the trace into one listing
//and rebase the main executable and libraries to the addresses occupied
//during the run. This allows the trace addresses to match the listing.
//@author
//@category TraceMadness
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class CombineTraceLibs extends GhidraScript {

	/**
	 * Parse the memory map into a convenient map
	 *
	 * @return Map<String, Long> library name -> virtual base address
	 */
	private Map<String, Long> loadAndParseMemoryMap (String mapfile)
	{
		Map<String, Long> store = new HashMap<String, Long>();
		
		try
		{
			String tmpStr 	= null;
			File memmap 	= null;
			
			String path = this.currentProgram.getExecutablePath();
			path = path.substring(0, path.lastIndexOf('/') + 1);
			
			memmap = new File(mapfile);
			Reader reader = new FileReader(memmap);
			BufferedReader buffReader = new BufferedReader(new FileReader(memmap));

			while ((tmpStr = buffReader.readLine()) != null)
			{
				StringTokenizer tmp = new StringTokenizer(tmpStr, " ");
				String libName = tmp.nextToken();
				Long address = Long.decode(tmp.nextToken());

                // If the libName starts with '[' it is likely either [vdso], [stack], or [heap].
                // Those are not backed by files that we drop in the sysroot so we skip them.
                if (libName.startsWith("[")) {
                    continue;
                }

				// want to place the lowest address
				// for each library, so if this
				// library is not in the map or if the
				// address currently stored is greater
				// than the one we've found, put this
				// address in for the library's base
				// address.
				if(!store.containsKey(libName) || store.get(libName) > address) {
				    store.put(libName, address);
				}
			}
			
			buffReader.close();
			reader.close();
			
			for (String key : store.keySet())
			{
				System.out.printf ("%s : 0x%x\n", key, store.get(key));
			}
		}
		catch (Exception e)
		{
			System.out.printf("Exception: %s", e);
		}
		
		return store;
	}
	
	/**
	 * Copy the functions from this library to the symbol manager of the 
	 * main binary
	 * 
	 * @param funcMan Function Manager for the main binary
	 * @param currentLibProg Program for the library
	 * @param importFuncIter Iterator over the libraries functions
	 * @throws InvalidInputException
	 * @throws OverlappingFunctionException
	 */
	private void copyOverFunctions(
			FunctionManager funcMan, 
			Program currentLibProg, 
			FunctionIterator importFuncIter) throws InvalidInputException, 
													OverlappingFunctionException
	{
		/*
		 * Insert the functions into the database and force 
		 * disassemble each one to encourage the analysis
		 */
		while (importFuncIter.hasNext())
		{
			Function tmpImportFunc = importFuncIter.next();
			if(currentLibProg.getMemory().getBlock(tmpImportFunc.getBody().getMinAddress()).getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) continue;
			if(currentLibProg.getMemory().getBlock(tmpImportFunc.getBody().getMinAddress()).getName().equals("tdb")) continue;
			
			funcMan.createFunction(
				tmpImportFunc.getName(),
				tmpImportFunc.getEntryPoint(), 
				tmpImportFunc.getBody(), 
				SourceType.USER_DEFINED
			);
			
			this.disassemble(tmpImportFunc.getEntryPoint());
		}
	}
	
	/**
	 * Copy all memory blocks (virtual memory) frtom the library to the main 
	 * binary
	 * 
	 * @param memory Memory of the main executalbe
	 * @param index Additional id to attach to the memory blocks name
	 * @param currentLibProg Current library to export blocks from
	 * @throws LockException
	 * @throws MemoryConflictException
	 * @throws AddressOverflowException
	 * @throws CancelledException
	 * @throws MemoryAccessException
	 */
	private void copyOverLibraryMemBlocks(
			Memory memory, 
			int index, 
			Program currentLibProg) throws 	LockException,
											MemoryConflictException, 
											AddressOverflowException, 
											CancelledException, 
											MemoryAccessException 
	{
		MemoryBlock[] blocks = currentLibProg.getMemory().getBlocks();
		int thelength = blocks.length;
		
		for (int blockIndex = 0; blockIndex < thelength; blockIndex++)
		{
			MemoryBlock block 	= blocks[blockIndex];
			if(block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) continue;
			if(block.getName().equals("tdb")) continue;
			Address base	 	= block.getStart();
			long theSize 		= block.getSize();
			String blockLabel 	= currentLibProg.getName() + "_" + index;
			
			if (base.getOffset() != 0)
			{
				MemoryBlock memBlock = memory.createInitializedBlock(
					blockLabel, 
					base, 
					theSize, 
					(byte) 0, 
					monitor,
					false
				);
				
				// Copy over the permissions
				memBlock.setRead(block.isRead());
				memBlock.setWrite(block.isWrite());
				memBlock.setExecute(block.isExecute());
				
				byte[] xferArray = new byte[(int)theSize];
				
				/*
				 * Can't write into uninitialized blocks. We could replace 
				 * these with initialized so we can update xrefs to follow  
				 * with clicks.
				 */
				if (block.isInitialized())
				{
					block.getBytes(base, xferArray);
					memBlock.putBytes(base, xferArray);
				}
			}
		}
	}
	
	/**
	 * Combine all libs in the memory map created while generating the trace
	 * into one project file recreating the memory map of the original process
	 * for the trace.
	 */
	@Override
	protected void run() throws Exception {
		GhidraState state 		= this.getState();
		Project project 		= state.getProject();
		ProjectData projData 	= project.getProjectData();
		DomainFolder folder 	= projData.getRootFolder();
		
		FunctionManager funcMan = this.currentProgram.getFunctionManager();
		
		AddressFactory addrFactory = this.getAddressFactory();
		AddressSpace ram = addrFactory.getAddressSpace("ram");
		
		Memory memory = this.currentProgram.getMemory();
		
		ArrayList<Program> libraries 	= new ArrayList<Program>();
		ArrayList<Address> bases 		= new ArrayList<Address>();
		Address mainImageBase 			= null;

		String[] args = getScriptArgs();
		String mapfile = args[0];
		String sysroot = args[1];
		if(sysroot.endsWith("/")) sysroot = sysroot.substring(0, sysroot.length()-1);
		Map<String, Long> store = loadAndParseMemoryMap(mapfile);
		
		/*
		 * Import all binaries in the store to the project
		 * TODO: Check not done already in case of multiple runs???
		 */
		for (String key : store.keySet())
		{
		    if (!key.endsWith(this.currentProgram.getName())) {
			// if the library is not the current program, then
			DomainFolder currentFolder = projData.getRootFolder();
			System.out.println(key);
			// traverse down to the file within the current project
			String[] path = ("sysroot"+key).split("/");
			for(int i = 0; i < path.length-1; i++) {
			    System.out.println(currentFolder + " -> " + path[i]);
			    DomainFolder[] fs = currentFolder.getFolders();
			    for(int j = 0; j < fs.length; j++) System.out.println(fs[j]);
			    currentFolder = currentFolder.getFolder(path[i]);
			    System.out.println(currentFolder);
			}
			DomainFile file = currentFolder.getFile(path[path.length-1]);
			DomainObject obj = file.getDomainObject(this, true, true, monitor);
			try {
			    Program prog = (Program) obj;
			    libraries.add(prog);
			    bases.add(ram.getAddress(store.get(key)));
			} catch(Exception e) {
			    continue;
			}
		    }
		    else {
			mainImageBase = ram.getAddress(store.get(key));
		    }
		}
		
		// Add each entry in the map to the address space
		try
		{	
			this.currentProgram.setImageBase(mainImageBase, true);
			
			for (int index = 0; index < libraries.size(); index++)
			{
				Program currentLibProg = libraries.get(index);
				Address currentLibBaseAddr = bases.get(index);
				
				FunctionIterator importFuncIter = 
					currentLibProg.getFunctionManager().getFunctions(true);
			
				int txid = currentLibProg.startTransaction("xlate-imagebase");
				currentLibProg.setImageBase(currentLibBaseAddr, true);
				currentLibProg.endTransaction(txid, true);
				
				copyOverLibraryMemBlocks(memory, index, currentLibProg);
				copyOverFunctions(funcMan, currentLibProg, importFuncIter);
			}
		}
		catch (Exception e)
		{
			throw new RuntimeException("Exception Building Memory", e);
		}
	}
}

