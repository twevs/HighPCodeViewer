/**
 *  Copyright 2023 Thomas "twevs" Evans
 *
 *  This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
 *  later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along with this program. If not, see
 *  <https://www.gnu.org/licenses/>. 
 */

package highpcodeviewer;

import java.awt.BorderLayout;
import java.awt.Rectangle;
import java.awt.geom.Rectangle2D;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.util.ProgramLocation;
import resources.Icons;

public class HighPCodeViewerProvider extends ComponentProviderAdapter {

	private JPanel panel;
	private JTextArea textArea;
	private Program currentProgram;
	private ProgramLocation currentLocation;
	private Function currentFunction;
	private DecompInterface ifc;
	
	class LineNumberPair
	{
		public LineNumberPair(int startLine, int endLine) {
			start = startLine;
			end = endLine;
		}
		public int start;
		public int end;
	}
	private Map<Address, LineNumberPair> addressLineNumberMap = new HashMap<Address, LineNumberPair>();

	public HighPCodeViewerProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildPanel();
		setIcon(Icons.HELP_ICON);
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setTitle("High P-Code Viewer");
		setVisible(true);
	}
	
	void initializeDecompiler()
	{
		ifc = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		ifc.setOptions(options);
		ifc.openProgram(currentProgram);
	}

	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		JScrollPane sp = new JScrollPane(textArea);
		panel.add(sp);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	void clear()
	{
		currentProgram = null;
		currentLocation = null;
		textArea.setText("");
	}
	
	void locationChanged(Program program, ProgramLocation location)
	{
		this.currentProgram = program;
		this.currentLocation = location;
		if (currentProgram == null || currentLocation == null)
		{
			return;
		}
		
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function newFunction = functionManager.getFunctionContaining(currentLocation.getAddress());
		boolean hasFunctionChanged = (newFunction != currentFunction);
		this.currentFunction = newFunction;
		if (currentFunction == null)
		{
			return;
		}
		
		if (hasFunctionChanged)
		{
			onFunctionChanged();
		}
		onLocationChanged();
	}
	
	void onFunctionChanged()
	{
		if (ifc == null)
		{
			initializeDecompiler();
		}
		DecompileResults decompResults = ifc.decompileFunction(currentFunction, 30, null);
		HighFunction highFunction = decompResults.getHighFunction();
		
		Iterator<PcodeOpAST> ast = highFunction.getPcodeOps();
		String preview = "";
		addressLineNumberMap.clear();
		Address functionEntryPoint = currentFunction.getEntryPoint();
		Address currentBlockStartAddress = functionEntryPoint;
		int currentBlockStartLine = 0;
		int lineNumberCount = 0;
		while (ast.hasNext())
		{
			PcodeOpAST currentOp = ast.next();
			Address opAddress = currentOp.getSeqnum().getTarget();
			if (currentBlockStartAddress == functionEntryPoint)
			{
				currentBlockStartAddress = opAddress;
			}
			else if (!opAddress.equals(currentBlockStartAddress))
			{
				addressLineNumberMap.put(currentBlockStartAddress, new LineNumberPair(currentBlockStartLine, lineNumberCount));
				currentBlockStartAddress = opAddress;
				currentBlockStartLine = lineNumberCount;
			}
			preview += opAddress + ": " + currentOp.toString() + "\n";
			lineNumberCount++;
		}
		textArea.setText(preview);
	}
	
	void onLocationChanged()
	{
		Address currentAddress = currentLocation.getAddress();
		if (!addressLineNumberMap.containsKey(currentAddress))
		{
			return;
		}
		LineNumberPair lineNumberPair = addressLineNumberMap.get(currentAddress);
		int startLine = lineNumberPair.start;
		int endLine = lineNumberPair.end;
		int startOffset = 0;
		int endOffset = 0;
		try {
			startOffset = textArea.getLineStartOffset(startLine);
			endOffset = textArea.getLineStartOffset(endLine);
		} catch (BadLocationException e) {
			e.printStackTrace();
		}
		textArea.setCaretPosition(startOffset);
		try {
			Rectangle2D rect = textArea.modelToView2D(startOffset);
			if (rect == null)
			{
				return;
			}
			int startY = (int) (rect.getY() + rect.getHeight() / 2);
			rect = textArea.modelToView2D(endOffset);
			int endY = (int) (rect.getY() + rect.getHeight() / 2);
			textArea.scrollRectToVisible(new Rectangle(0, startY, 0, endY - startY));
		} catch (BadLocationException e) {
			e.printStackTrace();
		}
		
		DefaultHighlighter highlighter = (DefaultHighlighter) textArea.getHighlighter();
		DefaultHighlighter.DefaultHighlightPainter myPainter = new DefaultHighlighter.DefaultHighlightPainter(java.awt.Color.YELLOW);
		highlighter.setDrawsLayeredHighlights(false);
		try {
			highlighter.removeAllHighlights();
			highlighter.addHighlight(textArea.getLineStartOffset(startLine), textArea.getLineStartOffset(endLine), myPainter);
		} catch (BadLocationException e) {
			e.printStackTrace();
		}
	}
}
