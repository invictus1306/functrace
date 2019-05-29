//ghidra coverage script (based on functrace)
//@author functrace Sindoni @invictus1306 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class functrace extends GhidraScript {
	private File report_file;
	private String comment_str = null;
	private ArrayList<String> pc_list = new ArrayList<String>();

	
	public void run() throws Exception {
		println("A Ghidra coverage script (based on functrace generated report) \n" +
				   "functrace - Andrea Sindoni (@invictus1306)" +
				   "\n");
		
		clearBackgroundColor(currentProgram.getMemory().getAllInitializedAddressSet());
		
		report_file = askFile("Please select the report file to analyze", "Load file");
		
		read_file(report_file.getAbsolutePath());
	}
   
	private void read_file(String file) {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(file));
			String line = reader.readLine();
			while (line != null) {
				parse_line(line, reader);
				line = reader.readLine();
			}
			reader.close();
		} catch (FileNotFoundException e) {
				e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (AddressFormatException e) {
			e.printStackTrace();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	private void parse_line(String line, BufferedReader reader) throws AddressFormatException {
		try {
			String[] split_line = line.split(";");
			
			if (split_line[0].contains("FUNC")) {
				String current_pc = split_line[3];
				pc_list.add(current_pc);
				coverage_info(current_pc, null);
			} else if (split_line[0].contains("ARG")) {
				comment_str = "";
				int num_args = Integer.parseUnsignedInt(split_line[4]);
				for (int k = 0; k < num_args; k++) {
					String arg_num = split_line[3];
					String value = split_line[5];
					comment_str += "Argument " + arg_num + " : " + value + "\n";
					
					split_line = inc_line("ARG", reader, arg_num);	
				}
			} else if (split_line[0].contains("RET")) {
				String address = split_line[2];
				String value = split_line[3];
				comment_str += "retrun value is " + value + "\n";
				inc_line("RET", reader, null);
				add_comment(address);
			} else if (split_line[0].contains("CRASH")) {
				boolean is_abort_signal = false;
				String signal_number = split_line[1];
				String signal_desc = split_line[2];
				String pc = split_line[3];
				if (6 == Integer.parseInt(signal_number)) {
					is_abort_signal = true;
					int size = pc_list.size();
					pc = pc_list.get(size -3);
				}
				if (is_abort_signal) {
					comment_str = "CRASH with SIGABRT " + pc + " signal: " + signal_number + "(" + signal_desc + ")" + "\n";
				} else {
					comment_str = "CRASH at " + pc + " signal: " + signal_number + "(" + signal_desc + ")" + "\n";
				}
				
				add_comment(pc);
				coverage_info(pc, "CRASH");    			
			}
		}catch(NumberFormatException e){
			e.printStackTrace();
		}
	}
	
	private String[] inc_line(String type, BufferedReader reader, String arg_num){
		String line = null;
		String[] split_line;
		
		try {
			line = reader.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (line == null)
			return null;
		
		split_line = line.split(";");
		int check_line_size = split_line.length;
		
		if (split_line[0].contains("DUMP")) {
			String dump = "Nothing to dump";
			if (check_line_size == 3) {
				dump = split_line[2];
			}
			
			if (type == "ARG") {			
				comment_str += "Argument " + arg_num + " is an address, dump: " + dump + "\n";
				try {
					line = reader.readLine();
				} catch (IOException e) {
					e.printStackTrace();
				}
				if (line == null)
					return null;
				split_line = line.split(";");
			} else if (type == "RET") {
				comment_str += "The retun valune is an address, dump: " + dump + "\n";
			}
		}
		return split_line;
	}
	
	private void coverage_info(String current_pc, String crash) throws AddressFormatException {
		AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address pc_address  = defaultAS.getAddress(current_pc);
		
		Instruction instruction = getInstructionAt(pc_address);

		while (true) {

			if (monitor.isCancelled()) {
				break;
			}
			
			if (instruction == null) {
				break;
			}
			
			Address curAddr = instruction.getAddress();
			
			if (crash == "CRASH") {
				setBackgroundColor(curAddr, Color.ORANGE);
				break;
			}
			
			setBackgroundColor(curAddr, Color.GREEN);
			
			if (!instruction.isFallthrough()) {
				setBackgroundColor(curAddr, Color.GREEN);
				break;
			}
			
			instruction = getInstructionAfter(instruction);
		}
	}

	private void add_comment(String address) throws AddressFormatException {
		AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address sym_address = defaultAS.getAddress(address);
		Listing listing = currentProgram.getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(sym_address);
		
		if (codeUnit != null) {
			codeUnit.setComment(CodeUnit.PLATE_COMMENT, comment_str);
		} else {
			println(comment_str);
		}
		
		comment_str = null;
	}
}