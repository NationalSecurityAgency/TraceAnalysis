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
//An example emulation script that emits trace information.
//It provides the set-up code and then outputs a trace binary.

//@author 
//@category Emulation
//@keybinding
//@menupath
//@toolbar


import java.nio.charset.Charset;

import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.lang.ConstantPool.Record;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pcode.emu.BytesPcodeThread;
import ghidra.pcode.emu.DefaultPcodeThread;
import ghidra.pcode.emu.SleighInstructionDecoder;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.pcode.opbehavior.*;

import java.io.OutputStream;
import java.io.FileOutputStream;
import java.util.Map;

import db.Transaction;

import java.util.HashMap;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.math.BigInteger;

public class TraceScript extends GhidraScript {
    private final static Charset UTF8 = Charset.forName("utf8");
    private class Tracer {
		
	/**
	 * Record type used to identify the file as a trace.
	 */
	private final static byte[] MagicBytes = new byte[]{0x65, 0x78, 0x00, 0x3c, 0x7f};
	private ArchKind currArch;
	public PcodeEmulator emulator;
				
	private OutputStream outputStream;
		
	public Tracer(String filename, String archKindString) throws Exception{
	    outputStream = new FileOutputStream(filename); //FIXME how do i close this? the finalize() is not right neither is try-with-resources.
	    currArch = this.getArchKind(archKindString);
	    emitRecord(RecordKind.MAGIC, MagicBytes);
	    emitArchRecord(currArch);
	}

	public static enum ArchKind {
		X86(new byte[]{(byte) 0x20}, 4, true),
		X86_64(new byte[]{(byte)0x40 }, 8, true),
		X86_64Compat32(new byte[]{(byte)0x21 }, 8, true),
		PowerPc(new byte[]{(byte) 0x10}, 4, false),
		PowerPc64(new byte[]{(byte) 0x11}, 8, false),
		Arm(new byte[]{(byte)0x12, (byte) 0x00 }, 4, true),
		Arm64(new byte[]{(byte) 0x12, (byte) 0x01}, 8, true),
		M68k(new byte[]{(byte) 0x01}, 4, false),
		Mips(new byte[]{(byte) 0x60}, 4, false),
		Mips64(new byte[]{(byte) 0x61}, 8, false),
		Mipsel(new byte[]{(byte) 0x62}, 4, true),
		Mipsel64(new byte[]{(byte) 0x63}, 8, true),
		Sparc(new byte[]{(byte) 0x80}, 4, false),
		Sparc64(new byte[]{(byte) 0x81}, 8, false),
		RiscV(new byte[]{(byte) 0x70}, 4, true),
		RiscV64(new byte[]{(byte) 0x71}, 8, true);

		private final byte[] value;
		private final boolean LEBool;
		private final int byteSize;
		ArchKind(byte[] value, int byteSize, boolean LEBool){
		    this.value = value;
		    this.byteSize = byteSize;
		    this.LEBool = LEBool;
		}
		byte[] getValue() {
		    return value;
		}
			
	    }

	    /**
	     * Retrieve the RecordKind based on a String version of the LanguageId 
	     * WARNING: This seem likes a poor method to retrieve this informaiton but it was the suggested method from others and i am not sure of a better way
	     * @param LanguageIdStr
	     * @return
	     * @throws Exception
	     */
	    public static ArchKind getArchKind(String LanguageIdStr) throws Exception{
		switch (LanguageIdStr) {
		case "x86:LE:64:default":
		    return Tracer.ArchKind.X86_64;
		    //TODO add all language types that map to ArchKind Enum. 
		default:
		    throw new Exception("Undefined mapping from LanguageId=`" + LanguageIdStr + "'");
		}
	    }

	    /**
	     * an structure to hold record kinds 
	     */
	    public static enum RecordKind {
			
		/**
		 * Record type used to identify the file as a trace.
		 */
		MAGIC ((byte) 0xf0),
			
		/**
		 * Record type used to specify the architecture of the program being traced.
		 */
		ARCH ((byte)0x00),
			
		/**
		 * Record type used to provide meta data that applies to the entire trace.
		 */
		FILE_META ((byte)0x04),
			
		/**
		 *  Record type that indicates that a new region of memory has been mapped in.
		 */
		MAP ((byte)0x10),
			
		/**
		 * Record type that indicates that a region of memory has been unmapped.
		 */
		UNMAP ((byte)0x1c),
			
		/**
		 * Record type that indicates that an instruction has been executed.
		 */
		INSTRUCTION ((byte) 0x20),
			
		/**
		 * Record type that indicates that a new instruction has been fetched.
		 */
		PC ((byte) 0x24),
			
		/**
		 * Record type that provides metadata to the following record(s).
		 */
		META ((byte) 0x30),
			
		/**
		 * Record type for an interupt
		 */
		INTERRUPT ((byte) 0x38),
			
		/**
		 * Record type that indicates that a register has been read from.
		 */
		REG_READ ((byte) 0x40),
			
		/**
		 * Record type that indicates that a register has been written to.
		 */
		REG_WRITE ((byte) 0x44),
			
		//			/**
		//			 * Record type that indicates that a register has been written to using the register number provided by the RegisterNameMap record.
		//			 */
		//			REG_WRITE_NATIVE ((byte) 0x54),
			
		/**
		 * Record type that indicates that a memory address has been read from.
		 */
		MEM_READ ((byte)0x80),
			
		/**
		 * Record type that indicates that a memory address has been written to.
		 */
		MEM_WRITE ((byte)0x84);
			

		private final byte value;
		RecordKind(byte value){
		    this.value = value;
		}
		byte getValue() {
		    return value;
		}
	    }
		
	    private static class VlenRlenObj {
		public final byte[] vlen;
		public final byte[] rlen;
			
		public VlenRlenObj(byte[] vlen, byte[] rlen) {
		    this.vlen = vlen;
		    this.rlen = rlen;
		}
			
	    }
		
	    private static byte VlenLenToLenLen (byte[] vlen) throws Exception {
		/*
		 * 00 = 0 bytes
		 * 01 = 1 byte
		 * 10 = 2 bytes
		 * 11 = 4 bytes
		 */	
		switch (vlen.length) {
		case 0 :
		    return 0b0000_0000;
		case 1 :
		    return 0b0000_0001;
		case 2 :
		    return 0b0000_0010;
		case 4 : 
		    return 0b0000_0011;
		default:
		    throw new Exception("Invaild Vlen Length");
		}
	    }

	    private static VlenRlenObj calc_vlen_rlen(long size) throws Exception{
		if (size < (0xff -1)) {
		    return new VlenRlenObj(u8(size+1), u8(1+1+size));
		} else if (((0xff -1) <= size)  | (size < (0xffff-4)))  {
		    return new VlenRlenObj(u16(size+4+1), u32(1+2+size));
		} else if (((0xffff - 4) <= size) | (size < 0xffff_ffffL- 4)) {
		    return new VlenRlenObj(u32(size+4+1), u32(1+4+size));
		} else {
		    throw new Exception("Data to large for record");
		}
		//throw new Exception("I should never get here there was an if else logic error");
			
	    }
				
	    public static byte[] u8 (long val) { 
		return new byte[]{(byte)val};
	    };
		
	    public static byte[] u16 ( long val) {
		byte[] bb = ByteBuffer.allocate(8).putLong(val).array(); 
		return new byte[] {bb[6], bb[7]};//TODO FIXME IT DONT THINK THIS IS RIGHT!!!!!
	    }
	    public static byte[] u32 ( long val) {
		byte[] bb = ByteBuffer.allocate(8).putLong(val).array();
		return new byte[] {bb[3], bb[2], bb[1], bb[0]}; //TODO FIXME I DONT THINK THIS IS RIGHT!!!!!
	    }

	    public static byte[] u32_BE ( long val) {
		return ByteBuffer.allocate(4).putLong(val).array();//TODO FIXME I DONT THINK THIS IS RIGHT!!!!!
	    }
	    public static byte[] u64 ( long val) {
		byte[] bb = ByteBuffer.allocate(8).putLong(val).array();
		return new byte[] {bb[7], bb[6], bb[5], bb[4], bb[3], bb[2], bb[1], bb[0]};//TODO FIXME I DONT THINK THIS IS RIGHT!!!!!
	    }
	    public static byte[] u64_BE ( long val) {
		return ByteBuffer.allocate(8).putLong(val).array(); //TODO FIXME I DONT THINK THIS IS RIGHT!!!!!
	    }

	    protected void emitRecord(Tracer.RecordKind kind, byte[] data ) throws Exception {
		//vlen, rlen = calculate_vlen_rlen(len(data));
		VlenRlenObj vro = calc_vlen_rlen(data.length);
			
			
		byte combinedKindLen = (byte)(kind.value | VlenLenToLenLen(vro.vlen));
		this.outputStream.write(combinedKindLen);
		this.outputStream.write(vro.vlen);
		this.outputStream.write(data);
		this.outputStream.write(vro.rlen);
			
	    }
		
		
	    protected void emitArchRecord(ArchKind archKind ) throws Exception {
		byte[] a = new byte[]{archKind.value[0],(byte)0,(byte)0,(byte)0};
		emitRecord(RecordKind.ARCH, a);
	    }

	    protected void emitMemReadRecord(byte[] offset, byte[] data ) throws Exception {
		byte[] rec = new byte[offset.length + data.length];
		System.arraycopy(offset, 0, rec, 0, offset.length);
		System.arraycopy(data, 0, rec, offset.length, data.length);
		emitRecord(RecordKind.MEM_READ, rec);
	    }

	    protected void emitMemWriteRecord(byte[] offset, byte[] data ) throws Exception {
		byte[] rec = new byte[offset.length + data.length];
		System.arraycopy(offset, 0, rec, 0, offset.length);
		System.arraycopy(data, 0, rec, offset.length, data.length);
		emitRecord(RecordKind.MEM_WRITE, rec);
	    }
	    
	    protected void emitRegWriteRecord(int regnum, byte[] data ) throws Exception {
		byte[] rec = new byte[4 + data.length];
		byte[] offset = ByteBuffer.allocate(4).order(currArch.LEBool ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN).putInt(regnum).array();
		System.arraycopy(offset, 0, rec, 0, offset.length);
		System.arraycopy(data, 0, rec, offset.length, data.length);
		emitRecord(RecordKind.REG_WRITE, rec);
	    }
	    protected void emitPcRecord(long pc) throws Exception {
		byte[] offset = ByteBuffer.allocate(8).order(currArch.LEBool ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN).putLong(pc).array();
		emitRecord(RecordKind.PC, offset);
	    }
	    protected void emitInsRecord(long pc, byte[] insbytes) throws Exception {
		byte[] rec = new byte[8 + insbytes.length];
		byte[] offset = ByteBuffer.allocate(8).order(currArch.LEBool ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN).putLong(pc).array();
		System.arraycopy(offset, 0, rec, 0, offset.length);
		System.arraycopy(insbytes, 0, rec, offset.length, insbytes.length);
		emitRecord(RecordKind.INSTRUCTION, rec);
	    }
	    public PcodeEmulator createEmulator(SleighLanguage language) {
		Tracer self = this;
		emulator = new PcodeEmulator(language) {
			protected BytesPcodeThread createThread(String name) {
			    return new BytesPcodeThread(name, this) {
				@Override protected PcodeThreadExecutor<byte[]> createExecutor() {
				    return new PcodeThreadExecutor<>(this) {
					@Override public void stepOp(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<byte[]> library) {
					    println(op.toString());
					    super.stepOp(op, frame, library);

					    Varnode outVar = op.getOutput();
						
					    if(op.getOpcode() == PcodeOp.LOAD) {
						int spaceID = getIntConst(op.getInput(0));
						AddressSpace space = language.getAddressFactory().getAddressSpace(spaceID);
						Varnode inOffset = op.getInput(1);
						byte[] offset = state.getVar(inOffset, reason);
						byte[] val = state.getVar(space, offset, outVar.getSize(), true, reason);
						print("MEM READ " + String.format("0x%x", arithmetic.toLong(offset, Purpose.LOAD)) + " " + outVar.getSize() + "\n VAL: ");
						for(int i = 0; i < val.length; i++) {
						    print(String.format("%02x ", val[i]));
						}
						print("\n");
						try {
						    self.emitMemReadRecord(offset, val);
						} catch(Exception e) {
						    e.printStackTrace();
						}
					    } else if(op.getOpcode() == PcodeOp.STORE) {
						int spaceID = getIntConst(op.getInput(0));
						AddressSpace space = language.getAddressFactory().getAddressSpace(spaceID);
						Varnode inOffset = op.getInput(1);
						byte[] offset = state.getVar(inOffset, reason);
						Varnode valVar = op.getInput(2);
						byte[] val = state.getVar(valVar, reason);
						print("MEM WRITE " + String.format("0x%x", arithmetic.toLong(offset, Purpose.LOAD)) + " " + valVar.getSize() + "\n VAL: ");
						for(int i = 0; i < val.length; i++) {
						    print(String.format("%02x ", val[i]));
						}
						print("\n");
						try {
						    self.emitMemWriteRecord(offset, val);
						} catch(Exception e) {
						    e.printStackTrace();
						}
					    }
						
					    OpBehavior b = OpBehaviorFactory.getOpBehavior(op.getOpcode());
					    if (b != null && (b instanceof UnaryOpBehavior unOp || b instanceof BinaryOpBehavior binOp)) {
						for(Varnode var : op.getInputs()) {
						    AddressSpace space = var.getAddress().getAddressSpace();
						    if(space.getType() == AddressSpace.TYPE_RAM ) {

							byte[] offset = Tracer.u64(var.getOffset());
							byte[] val = state.getVar(var, reason);
							print("OTHER MEM READ " + String.format("0x%x", arithmetic.toLong(offset, Purpose.LOAD)) + " " + var.getSize() + "\n VAL: ");
							for(int i = 0; i < val.length; i++) {
							    print(String.format("%02x ", val[i]));
							}
							print("\n");
							try {
							    self.emitMemReadRecord(offset, val);
							} catch(Exception e) {
							    e.printStackTrace();
							}
							    
						    }
						}
					    }
					    if(outVar != null && outVar.getAddress().getAddressSpace().getType() == AddressSpace.TYPE_REGISTER) {
						byte[] val = state.getVar(outVar.getAddress().getAddressSpace(), outVar.getAddress().getOffset(), outVar.getSize(), true, reason);
						print("REG WRITE " + outVar.getAddress().toString() + " \n VAL: ");
						for(int i = 0; i < val.length; i++) {
						    print(String.format("%02x ", val[i]));
						}
						print("\n");
						try {
						    self.emitRegWriteRecord((int)outVar.getAddress().getOffset(), val);
						} catch(Exception e) {
						    e.printStackTrace();
						}
					    }
					    if(outVar != null && outVar.getAddress().getAddressSpace().getType() == AddressSpace.TYPE_RAM) {
						byte[] offset = Tracer.u64(outVar.getOffset());
						byte[] val = state.getVar(outVar, reason);
						print("OTHER MEM WRITE " + String.format("0x%x", arithmetic.toLong(offset, Purpose.LOAD)) + " " + outVar.getSize() + "\n VAL: ");
						for(int i = 0; i < val.length; i++) {
						    print(String.format("%02x ", val[i]));
						}
						print("\n");
						try {
						    self.emitMemReadRecord(offset, val);
						} catch(Exception e) {
						    e.printStackTrace();
						}
					    }
					}
				    };
				}

				@Override
				public void executeInstruction() {
				    Instruction instruction = decoder.decodeInstruction(getCounter(), getContext());
				    Address pc = getCounter();
				    print("PC " + pc.toString()+":"+instruction.toString()+"\n");
				    try {
					self.emitPcRecord(pc.getOffset());
				    } catch(Exception e) {
					e.printStackTrace();
				    }
				    super.executeInstruction();
					
				    print("INS " + instruction.toString()+"\n");
				    try {
					self.emitInsRecord(pc.getOffset(), instruction.getParsedBytes());
				    } catch(Exception e) {
					e.printStackTrace();
				    }
				} 
				@Override
				protected SleighInstructionDecoder createInstructionDecoder(PcodeExecutorState<byte[]> sharedState) {
				    return new SleighInstructionDecoder(language, sharedState) {
					@Override
					public Instruction decodeInstruction(Address address, RegisterValue context) {
					    Instruction instruction = super.decodeInstruction(address, context);
					    return instruction;
					}
				    };
				}
			    };
			}
			
		};
		this.emulator = emulator;
		return emulator;
	    }
	    public BytesPcodeThread createThread(String name, Address entrypoint, Program program) {
		AddressSpace space = program.getLanguage().getDefaultSpace();
		BytesPcodeThread thread = (BytesPcodeThread)this.emulator.newThread(name);
		PcodeUseropLibrary<byte[]> library = thread.getUseropLibrary();
		for(MemoryBlock block : currentProgram.getMemory().getBlocks()) {
		    byte[] data = new byte[(int)block.getSize()];
		    try {
			block.getBytes(block.getStart(), data);
			thread.getState().getSharedState().setVar(space, block.getStart().getOffset(), (int)block.getSize(), true, data);
			print(block.getStart().toString() + "\n");
			for(int i = 0; i < (int)block.getSize(); i++) {
			    print(String.format("%02x ", data[i]));
			}
			print("\n");
		    } catch(Exception exc) {
			continue;
		    }
		}
		
		thread.overrideContextWithDefault();
		thread.reInitialize();
		thread.setCounter(entrypoint);
		return thread;
	    }
	}

	@Override
	protected void run() throws Exception {
		SleighLanguage language = (SleighLanguage) getLanguage(currentProgram.getLanguageID());
		AddressSpace dyn = language.getDefaultSpace();
		try {
		    Tracer t = new Tracer("/tmp/ghidra.trace", currentProgram.getLanguageID().getIdAsString());
		
		
		    Address entryAddr = dyn.getAddress(0x00401000L);
		    t.createEmulator(language);
		    BytesPcodeThread thread = t.createThread("trace", entryAddr, currentProgram);
		    try {
			while(true) {
			    thread.stepInstruction();
			}
		    }
		    catch (InterruptPcodeExecutionException e) {
			println("Exception: " + e);
			return;
		    }	
		}
		catch (Exception e) {
		    println("Exception: " + e);
		    return;
		}
	}
}
